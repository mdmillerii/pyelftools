#-------------------------------------------------------------------------------
# elftools: dwarf/locationlists.py
#
# DWARF location lists section decoding (.debug_loc)
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
from collections import namedtuple

from ..common.utils import struct_parse

LocationExpr = namedtuple('LocationExpr', 'loc_expr')
LocationEntry = namedtuple('LocationEntry', 'begin_offset end_offset loc_expr')
BaseAddressEntry = namedtuple('BaseAddressEntry', 'base_address')

class LocationLists(object):
    """ A single location list is a Python list consisting of LocationEntry or
        BaseAddressEntry objects.
    """
    def __init__(self, stream, structs):
        self.stream = stream
        self.structs = structs
        self._max_addr = 2 ** (self.structs.address_size * 8) - 1

    def get_location_list_at_offset(self, offset):
        """ Get a location list at the given offset in the section.
        """
        self.stream.seek(offset, os.SEEK_SET)
        return self._parse_location_list_from_stream()

    def iter_location_lists(self):
        """ Yield all location lists found in the section.
        """
        # Just call _parse_location_list_from_stream until the stream ends
        self.stream.seek(0, os.SEEK_END)
        endpos = self.stream.tell()

        self.stream.seek(0, os.SEEK_SET)
        while self.stream.tell() < endpos:
            yield self._parse_location_list_from_stream()

    #------ PRIVATE ------#

    def _parse_location_list_from_stream(self):
        lst = []
        while True:
            begin_offset = struct_parse(
                self.structs.Dwarf_target_addr(''), self.stream)
            end_offset = struct_parse(
                self.structs.Dwarf_target_addr(''), self.stream)
            if begin_offset == 0 and end_offset == 0:
                # End of list - we're done.
                break
            elif begin_offset == self._max_addr:
                # Base address selection entry
                lst.append(BaseAddressEntry(base_address=end_offset))
            else:
                # Location list entry
                expr_len = struct_parse(
                    self.structs.Dwarf_uint16(''), self.stream)
                loc_expr = [struct_parse(self.structs.Dwarf_uint8(''),
                                         self.stream)
                                for i in range(expr_len)]
                lst.append(LocationEntry(
                    begin_offset=begin_offset,
                    end_offset=end_offset,
                    loc_expr=loc_expr))
        return lst

class LocationParser(object):
    """ A parser for location information in DIEs.
        Handles both location information contained within the attribute
        itself (represented as a LocationExpr object) and references to
        location lists in the .debug_loc section (represented as a
        list).
    """
    def __init__(self, location_lists):
        self.location_lists = location_lists

    @staticmethod
    def attribute_has_location(attr, dwarf_version):
        """ Checks if a DIE attribute contains location information.
        """
        return (LocationParser._attribute_is_loclistptr_class(attr) and
                (LocationParser._attribute_has_loc_expr(attr, dwarf_version) or
                 LocationParser._attribute_has_loc_list(attr, dwarf_version)))

    def parse_from_attribute(self, attr, dwarf_version):
        """ Parses a DIE attribute and returns either a LocationExpr or
            a list.
        """
        if self.attribute_has_location(attr, dwarf_version):
            if self._attribute_has_loc_expr(attr, dwarf_version):
                return LocationExpr(attr.value)
            elif self._attribute_has_loc_list(attr, dwarf_version):
                return self.location_lists.get_location_list_at_offset(
                    attr.value)
        else:
            raise ValueError("Attribute does not have location information")

    #------ PRIVATE ------#

    @staticmethod
    def _attribute_has_loc_expr(attr, dwarf_version):
        return (dwarf_version < 4 and attr.form == 'DW_FORM_block1' or
                attr.form == 'DW_FORM_exprloc')

    @staticmethod
    def _attribute_has_loc_list(attr, dwarf_version):
        return ((dwarf_version < 4 and
                 attr.form in ('DW_FORM_data4', 'DW_FORM_data8')) or
                attr.form == 'DW_FORM_sec_offset')

    @staticmethod
    def _attribute_is_loclistptr_class(attr):
        return (attr.name in ( 'DW_AT_location', 'DW_AT_string_length',
                               'DW_AT_const_value', 'DW_AT_return_addr',
                               'DW_AT_data_member_location',
                               'DW_AT_frame_base', 'DW_AT_segment',
                               'DW_AT_static_link', 'DW_AT_use_location',
                               'DW_AT_vtable_elem_location'))

class LocationFinder(object):
    """ Find a location expression given an attribute name and a DIE
    """
    def __init__(self, die, attr_name):
        """ Instantiate a LocationFinder to find the valid DWARF expressions
            defining the attribute for a given address.
        """
        self.attr = die.get_attribute(attr_name)
        if self.attr is None:
            raise KeyError('DIE %s has no attribute %s' %
                    (die.offset, attr_name))

        if self.is_exprloc:
            return

        version = die.cu['version']
        parser = LocationParser(die.cu.dwarfinfo.location_lists())

        # Parse the location list (or find it is an old expression form)
        if not parser.attribute_has_location(self.attr, version):
            raise TypeError

        self.loclist = parser.parse_from_attribute(self.attr, version)

        # Check if an early version block
        if self.is_expr:
            return

        # Otherwise check if the compile unit DIE defines a base address
        self.low_pc = die.cu.get_top_DIE().get_attribute('DW_AT_low_pc')

    @property
    def is_exprloc(self):
        """ Is the attribute of form DW_AT_exprloc ?
        """
        return self.attr.form == 'DW_FORM_exprloc'

    @property
    def is_expr(self):
        """ The attribute value contains the sole expression

            The location is valid if the DIE heirarchy is in scope.
        """
        return self.is_exprloc or isinstance(self.loclist, LocationExpr)

    def iter_expr(self, address):
        """ Iterate over the attributes location list provding each
            expression that is valid for the given address.
        """

        if self.is_expr:
            yield self.attr.value
            return

        base = None

        if self.low_pc:
            base = self.low_pc.value

        for e in self.loclist:
            if isinstance(e, BaseAddressEntry):
                base = e.base_address
                continue

            dwarf_assert(
                isinstance(e, LocationEntry),
                'Unexpected location list entry %s' % e)

            if base is None:
                raise ValueError('Invalid location list: no base availible')

            if base + begin_offset <= address < base + end_offset:
                yield e.loc_expr

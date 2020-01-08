#-------------------------------------------------------------------------------
# elftools: dwarf/die.py
#
# DWARF Debugging Information Entry
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from collections import namedtuple, OrderedDict
import os

from ..common.exceptions import DWARFError
from ..common.py3compat import bytes2str, iteritems, str2bytes
from ..common.utils import struct_parse, preserve_stream_pos, dwarf_assert
from .enums import DW_FORM_raw2name
# for DW_LANG_
from .constants import *

from .dwarf_expr import GenericExprVisitor
class ExtractAddress(GenericExprVisitor):
    def __init__(self, structs):
        self.address = None
        super(ExtractAddress, self).__init__(structs)

    def parse_locexpr(self, expr):
        self.address = None
        self.process_expr(expr)
        return self.address

    def _after_visit(self, opcode, name, args):
        if name == 'DW_OP_addr':
            self.address = args[0]
        else:
            raise NotImplementedError(("Need to handle opcode %s %x" % (name, opcode)))

class BitOffset(object):
            def __init__(self, byte_amount, bit_amount=0):
                self.bytes = byte_amount
                self.bits = bit_amount
            def add_to(self, base):
                if self.bits:
                    return BitOffset(base.bytes, self.bits + base.bits)
                return BitOffset(self.bytes + base.bytes)


# AttributeValue - describes an attribute value in the DIE:
#
# name:
#   The name (DW_AT_*) of this attribute
#
# form:
#   The DW_FORM_* name of this attribute
#
# value:
#   The value parsed from the section and translated accordingly to the form
#   (e.g. for a DW_FORM_strp it's the actual string taken from the string table)
#
# raw_value:
#   Raw value as parsed from the section - used for debugging and presentation
#   (e.g. for a DW_FORM_strp it's the raw string offset into the table)
#
# offset:
#   Offset of this attribute's value in the stream (absolute offset, relative
#   the beginning of the whole stream)
#
AttributeValue = namedtuple(
    'AttributeValue', 'name form value raw_value offset')

class DIE(object):
    """ A DWARF debugging information entry. On creation, parses itself from
        the stream. Each DIE is held by a CU.

        Accessible attributes:

            tag:
                The DIE tag

            size:
                The size this DIE occupies in the section

            offset:
                The offset of this DIE in the stream

            attributes:
                An ordered dictionary mapping attribute names to values. It's
                ordered to preserve the order of attributes in the section

            has_children:
                Specifies whether this DIE has children

            abbrev_code:
                The abbreviation code pointing to an abbreviation entry (note
                that this is for informational pusposes only - this object
                interacts with its abbreviation table transparently).

        See also the public methods.
    """
    def __init__(self, cu, stream, offset):
        """ cu:
                CompileUnit object this DIE belongs to. Used to obtain context
                information (structs, abbrev table, etc.)

            stream, offset:
                The stream and offset into it where this DIE's data is located
        """
        self.cu = cu
        self.dwarfinfo = self.cu.dwarfinfo # get DWARFInfo context
        self.stream = stream
        self.offset = offset

        self.attributes = OrderedDict()
        self.tag = None
        self.has_children = None
        self.abbrev_code = None
        self.size = 0
        # Null DIE terminator. It can be used to obtain offset range occupied
        # by this DIE including its whole subtree.
        self._terminator = None
        self._parent = None

        self._parse_DIE()

    def get_attribute(self, name, default=None):
        """ Get an attribute, considering attributes inherited from a
            DW_AT_specification or DW_AT_abstract_origin reference
        """
        if name in self.attributes:
            return self.attributes.get(name, default)

        # DWARF5 6.1.1.1 , 7.32, 3.3.8.2
        for ref in ('DW_AT_specification', 'DW_AT_abstract_origin'):
            if ref in self.attributes:
                link = self.get_DIE_from_attribute(ref)
                return link.get_attribute(name, default)

        return default

    def is_null(self):
        """ Is this a null entry?
        """
        return self.tag is None

    def get_DIE_from_attribute(self, name):
        """ Follow a die attribute in the reference class selected by
            name to the referenced DIE.

            These attributes will instantate other objects and so are only
            referenced on demand.
        """
        attr = self.get_attribute(name)
        if attr is None:
            return None
        elif attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4',
                         'DW_FORM_ref8', 'DW_FORM_ref'):
            refaddr = self.cu.cu_offset + attr.raw_value
            return self.cu.get_DIE_from_refaddr(refaddr)
        elif attr.form in ('DW_FORM_refaddr'):
            return self.cu.dwarfinfo.get_DIE_from_refaddr(attr.raw_value)
        elif attr.form in ('DW_FORM_ref_sig8'):
            # Implement search type units for matching signature
            raise NotImplementedError('%s (type unit by signature)' % attr.form)
        elif attr.form in ('DW_FORM_ref_sup4', 'DW_FORM_ref_sup8'):
            raise NotImplementedError('%s to dwo' % attr.form)
        else:
            raise DWARFError('%s is not a reference class form attribute' % attr)

    def new_iter_type(self):
        die = self
        while True:
            die = die.get_DIE_from_attribute('DW_AT_type')
            if die is None:
                return
            yield die

    def new_expand_type(self, var_name, offset):
        for t in self.new_iter_type():
            if t.get_byte_or_bit('DW_AT_byte_size', 'DW_AT_bit_size'):
                yield(var_name, [ self, t ], offset)
            if t.tag in ('DW_TAG_array_type'):
                for l in t.new_expand_array(var_name, offset):
                    yield l
                return
            elif t.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
                # DW_TAG_class, DW_TAG_instance ?
                for l in t.new_expand_struct(var_name, offset):
                    yield l
                return
            elif t.tag in ('DW_TAG_class_type', 'DW_TAG_instance_type'):
                for l in t.new_expand_struct(var_name, offset):
                    yield l
                return
            elif t.get_byte_or_bit('DW_AT_byte_size', 'DW_AT_bit_size'):
                # yield(var_name, [ self, t ], offset)
                return

    def new_expand_struct(self, var_name, offset):
        for child in self.iter_children():
            if child.tag == 'DW_TAG_member':
                # fixme: can be an expression not a constant, pass
                # offset on stack for expresson eval, get addr or reg
                m_offset = child.get_byte_or_bit('DW_AT_data_member_location',
                        'DW_AT_data_bit_offset')
                if m_offset:
                    off = m_offset.add_to(offset)
                else:
                    off = offset
                mn = child.get_attribute('DW_AT_name')
                if mn:
                    vn = b'.'.join((var_name, mn.value))
                else:
                    vn = var_name
                # else anon struct / union member
                for l in child.new_expand_type(vn, off):
                    yield l
            elif True:
                # These are only expected for classes and inheritance
                pass
            elif child.tag in ('DW_TAG_access_declaration',
                    'DW_TAG_friend', 'DW_TAG_variable', 'DW_AT_subprogram',
                    'DW_TAG_variant_part'):
                pass
            else:
                # What is this
                pass

    def new_expand_array(self, var_name, offset):
        """ Expand an array by iterating the subrange children with
            increasing offsets
        """

        order = self.get_attribute('DW_AT_ordering')
        dim = []
        gs = None

        for child in self.iter_children():
            if child.tag in ('DW_TAG_subrange_type', 'DW_TAG_enumeration_type'):
                dim.append(child)
            elif child.tag in ('DW_TAG_generic_subrange_type'):
                dim.insert(0, child)

        dwarf_assert(
            len(dim) >= 1,
            'Missing array dimension of DIE %s' % self.offset)
        dwarf_assert(
            dim[0].tag != 'DW_AT_generic_subrange' or len(dim) == 1,
                'DW_AT_generic_subrange must be only subrange of DIE %s' %
                self.offset)

        if order and order.value == DW_ORD_row_major:
            dim = reverse(dim)

        stride = self.get_byte_or_bit('DW_AT_byte_stride', 'DW_AT_bit_stride')

        for t in self.new_iter_type():
            if stride:
                break
            stride = t.get_byte_or_bit('DW_AT_byte_size', 'DW_AT_bit_size')

        dwarf_assert(
            stride,
                'Unknown array element size for %s' % self.offset)

        # recurise to loop over each iter
        for l in self.new_expand_array_ranges(var_name, '', offset, stride,
                order, dim):
            yield l

    def new_expand_array_ranges(self, var_name, icol, offset, stride, order, dims):
        """ Helper for new_expand_array() to recursivly walk one subrange.
        """
        dim = dims.pop(0)
        for (d, o, i) in dim.enumerate_array_rank(offset, stride):
            cols = ''.join(('[%s]' % d, icol))
            vn = b''.join((var_name, str2bytes(cols)))
            if not dims:
                for l in self.new_expand_type(vn, o):
                    yield l
                    o = i.add_to(o)
                continue

            # reset either vn+rows or columns depeinding on insertion point
            if order.value == DW_ORD_col_major:
                # the cols fields will prepend, reset var_name
                vn = var_name
            elif order.value == DW_ORD_row_major:
                # the var name fields will append, reset cols
                cols = icol
            else:
                raise ValueError('order.value %s: unknown order' % order.value)
            # iterate on the next range
            for l in self.new_expand_arrray_ranges(vn, cols, o, stride,
                    order, dims):
                yield l
                o = i.add_to(o)

    def get_name(self, default=None):
        attr = self.get_attribute('DW_AT_name')
        if attr:
            vn = attr.value
        else:
            vn = default
        return vn

    def get_type_name(self, base=''):
        """ Print the name of a type, using tags for the modifiers
        """
        tn = base
        mn = None
        for t in self.new_iter_type():
            tn = tn + t.tag + ' '
            mn = t.get_name()
            if mn:
                return tn + bytes2str(mn)
        return tn

    def new_print_elems(self, offset=None, debug=0):
        """ Original wrapper to print elemens and types
        """
        vn = self.get_name(b'<base>')
        if self.tag in ('DW_TAG_variable'):
            loc = self.get_attribute('DW_AT_location')
            if loc:
                if loc.form in ('DW_FORM_exprloc'):
                    ed = ExtractAddress(self.cu.structs)
                    # TODO: eval location with (likely) OP_address
                    # offset = BitOffset.eval(expr)
                    offset = BitOffset(ed.parse_locexpr(loc.value))
                else:
                    raise NotImplementedError('DIE %s location form %s' % (
                        self.offset, loc.form))
            else:
                raise KeyError('DIE %s location key %s' % (
                        self.offset, 'DW_AT_location'))

        if offset is None:
            offset = BitOffset(0)

        for (n, mod, o) in self.new_expand_type(vn, offset):
            off = '(%#x,%s)' % (o.bytes, o.bits)
            tn = mod[0].get_type_name()
            sz = mod[-1].get_byte_or_bit('DW_AT_byte_size', 'DW_AT_bit_size')
            if sz:
                size = '(%#x,%s)' % (sz.bytes, sz.bits)
            else:
                size = '(unknown)'
            print ('%s is %s occuping %s at %s' % (n, tn, size, off))

    # DWARFv5 Table 7.17
    def get_default_lower_bound(self):
        """ Get the implicit lower bound consindering the language of the
            compile unit.
            See DWARFv5 table 7.17.
        """
        # consider putting in cu class
        lang = self.cu.get_top_DIE().get_attribute('DW_AT_language')
        dwarf_assert(
            lang,
            'No language specified and no lower bound for DIE %s' %
            self.offset)
        if lang.value in (DW_LANG_C89, DW_LANG_C,
                DW_LANG_C_plus_plus, DW_LANG_C99, DW_LANG_Java):
            return 0
        elif lang.value in (DW_LANG_Fortran77, DW_LANG_Fortran90,
                DW_LANG_Fortran95, DW_LANG_Fortran03, DW_LANG_Fortran03):
            return 1
        # Fill in more from table language
        raise NotImplementedError("Find Language %s in table 7.17" % lang.value)

    def get_byte_or_bit(self, byte_name, bit_name):
        """ Look for a byte property, or if not found, look for a bit property

            Returns a BitOffset structure with the values.
        """
        ### Fixme : will need to consider FORM , can be an expression
        size = self.get_attribute(byte_name)
        if size:
            return BitOffset(size.value)
        size = self.get_attribute(bit_name)
        if size:
            return BitOffset(0, size.value)
        return None

    def enumerate_array_rank(self, offset, increment):
        """ Iterate over the given array rank (dimension)
        """
        stride = self.get_byte_or_bit('DW_AT_stride', 'DW_AT_bit_stride')
        if stride:
            increment = stride

        # Key error if the enumerator is not found
        enumerator = self.enumeration_iters[self.tag]
        for i in enumerator(self):
            yield (i, offset, increment)
            offset = increment.add_to(offset)

    def enumerate_generic_subrange_type(self):
        if self.tag == 'DW_TAG_generic_subrange_type':
            raise NotImplementedError('DIE %s: No generic_subrange_type support yet' % self.offset)
        raise ValueError('DIE %s: not DW_TAG_generic_subrange' % self.offset)

    def enumerate_subrange(self):
        if self.tag == 'DW_TAG_subrange_type':
            lb = self.get_attribute('DW_AT_lower_bound')
            if lb:
                lb = lb.value
            else:
                lb = self.get_default_lower_bound()
            count = self.get_attribute('DW_AT_count')
            if count:
                for i in range(count.value):
                    yield (lb + i)
                return
            ub = self.get_attribute('DW_AT_upper_bound')
            if ub:
                for i in range(lb, ub.value + 1):
                    yield (i)
                return
            # could become a default generator by parameter?
            return StopIteration('Unnown bounds')
        raise ValueError('DIE %s: not DW_TAG_subrange_type' % self.offset)

    def enumerate_enumerated_type(self):
        if self.tag == 'DW_TAG_enumerated_type':
            # DW_AT_enum_class possible
            for child in self.iter_children:
                if child.tag == 'DW_TAG_enumerator':
                    cvalue = child.get.attribute('DW_AT_const_value')
                    dwarf_assert(
                        cvalue,
                        'Enumerator %s missing values' % self.offset)
                    yield (cvalue.value)
                else:
                    # What other children would we expect?
                    pass
            return
        raise ValueError('DIE %s: not DW_TAG_enumerated_type' % self.offset)

    enumeration_iters = {
        'DW_TAG_subrange_type': enumerate_subrange,
        'DW_TAG_enumerated_type': enumerate_enumerated_type,
        'DW_TAG_generic_subrange_type': enumerate_generic_subrange_type,
        }

    def get_parent(self):
        """ The parent DIE of this DIE. None if the DIE has no parent (i.e. a
            top-level DIE).
        """
        if self._parent is None:
            self._search_for_ancestors()
        return self._parent

    def get_full_path(self):
        """ Return the full path filename for the DIE.

            The filename is the join of 'DW_AT_comp_dir' and 'DW_AT_name',
            either of which may be missing in practice. Note that its value is
            usually a string taken from the .debug_string section and the
            returned value will be a string.
        """
        comp_dir_attr = self.attributes.get('DW_AT_comp_dir', None)
        comp_dir = bytes2str(comp_dir_attr.value) if comp_dir_attr else ''
        fname_attr = self.attributes.get('DW_AT_name', None)
        fname = bytes2str(fname_attr.value) if fname_attr else ''
        return os.path.join(comp_dir, fname)

    def iter_children(self):
        """ Iterates all children of this DIE
        """
        return self.cu.iter_DIE_children(self)

    def iter_siblings(self):
        """ Yield all siblings of this DIE
        """
        parent = self.get_parent()
        if parent:
            for sibling in parent.iter_children():
                if sibling is not self:
                    yield sibling
        else:
            raise StopIteration()

    # The following methods are used while creating the DIE and should not be
    # interesting to consumers
    #

    def set_parent(self, die):
        self._parent = die

    #------ PRIVATE ------#

    def _search_for_ancestors(self):
        """ Search for our parent by starting with the CU top die and
            iteriating the children of the searched die and recording the
            the each child's _parent link, then iterate down the child DIE
            whose offset is nearest but less than our offset.
        """
        search = self.cu.get_top_DIE()
        # We could interate as soon as we find our younger parent's sibling
        # but that would require the same walks for our next sibling.

        while search.offset < self.offset:

            prev = search
            for child in search.iter_children():
                child.set_parent(search)
                if child.offset <= self.offset:
                    prev = child

            # We need to check if the offset is the terminator
            if search.has_children and search._terminator.offset <= self.offset:
                    prev = search._terminator

            # If we didn't find a closer parent, give up, don't loop.
            # Either we mis-parsed an ancestor or someone asked for a DIE
            # by an offset that was not actually the start of a DIE.
            if prev is search:
                raise ValueError("offset %s not in CU %s DIE tree" %
                    (self.offset, self.cu.cu_offset))

            search = prev

        pass
        # if search.offset != self.offset
        #    raise ValueError("offset %s not in DIE %s tree" % (offset,
        #       search.offset)

    def __repr__(self):
        s = 'DIE %s, size=%s, has_children=%s\n' % (
            self.tag, self.size, self.has_children)
        for attrname, attrval in iteritems(self.attributes):
            s += '    |%-18s:  %s\n' % (attrname, attrval)
        return s

    def __str__(self):
        return self.__repr__()

    def _parse_DIE(self):
        """ Parses the DIE info from the section, based on the abbreviation
            table of the CU
        """
        structs = self.cu.structs

        # A DIE begins with the abbreviation code. Read it and use it to
        # obtain the abbrev declaration for this DIE.
        # Note: here and elsewhere, preserve_stream_pos is used on operations
        # that manipulate the stream by reading data from it.
        self.abbrev_code = struct_parse(
            structs.Dwarf_uleb128(''), self.stream, self.offset)

        # This may be a null entry
        if self.abbrev_code == 0:
            self.size = self.stream.tell() - self.offset
            return

        abbrev_decl = self.cu.get_abbrev_table().get_abbrev(self.abbrev_code)
        self.tag = abbrev_decl['tag']
        self.has_children = abbrev_decl.has_children()

        # Guided by the attributes listed in the abbreviation declaration, parse
        # values from the stream.
        for name, form in abbrev_decl.iter_attr_specs():
            attr_offset = self.stream.tell()
            raw_value = struct_parse(structs.Dwarf_dw_form[form], self.stream)

            value = self._translate_attr_value(form, raw_value)
            self.attributes[name] = AttributeValue(
                name=name,
                form=form,
                value=value,
                raw_value=raw_value,
                offset=attr_offset)

        self.size = self.stream.tell() - self.offset

    def _translate_attr_value(self, form, raw_value):
        """ Translate a raw attr value according to the form
        """
        value = None
        if form == 'DW_FORM_strp':
            with preserve_stream_pos(self.stream):
                value = self.dwarfinfo.get_string_from_table(raw_value)
        elif form == 'DW_FORM_flag':
            value = not raw_value == 0
        elif form == 'DW_FORM_flag_present':
            value = True
        elif form == 'DW_FORM_indirect':
            try:
                form = DW_FORM_raw2name[raw_value]
            except KeyError as err:
                raise DWARFError(
                        'Found DW_FORM_indirect with unknown raw_value=' +
                        str(raw_value))

            raw_value = struct_parse(
                self.cu.structs.Dwarf_dw_form[form], self.stream)
            # Let's hope this doesn't get too deep :-)
            return self._translate_attr_value(form, raw_value)
        else:
            value = raw_value
        return value

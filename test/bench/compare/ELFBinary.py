from Binary import Binary
from datapoints.Symbol import Symbol, SymbolType
from datapoints.Data import Addr

from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from elftools.elf.sections import SymbolTableSection, Section
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.die import DIE
from elftools.dwarf.descriptions import describe_form_class
import logging as log


def symbol_type(type_str: str) -> SymbolType:
    if type_str == "STT_OBJECT":
        return SymbolType.OBJECT
    elif type_str == "STT_FUNC":
        return SymbolType.FUNCTION
    return SymbolType.UNSPECIFIED


class ELFBinary(Binary):
    def __init__(self, bin_path: Path):
        super().__init__(bin_path)

    def _load_obj(self):
        self.obj: ELFFile = ELFFile(open(self.path, "rb"))
        self.debug_info: DWARFInfo | None = (
            self.obj.get_dwarf_info() if self.obj.has_dwarf_info() else None
        )
        self._load_symbols()

    def can_load(bin_path: Path) -> bool:
        try:
            ELFFile.load_from_path(bin_path)
            return True
        except ELFError as e:
            log.debug(repr(e))
            return False

    def _load_symbols(self):
        self._load_elf_symbols()
        self._add_dwarf_symbols_data()
        self._clean_up_symbols()
        # log.debug("Symbols added")
        # for sym in self.symbols.values():
        #     log.debug(f"\t{sym}")

    def _load_elf_symbols(self):
        """
        Load FUNC and OBJECT symbols from ELF header.
        """
        sec: Section
        for sec in self.obj.iter_sections():
            if sec["sh_type"] != "SHT_SYMTAB" and sec["sh_type"] != "SHT_DYNSYM":
                continue
            log.debug(
                f"Parse section {sec['sh_type']} with {sec.num_symbols()} symbols."
            )

            table: SymbolTableSection = sec
            sym: Symbol
            for sym in table.iter_symbols():
                sym_type = symbol_type(sym.entry["st_info"]["type"])
                sym_size = sym.entry["st_size"]
                loc = sym.entry["st_value"]
                if loc == 0:
                    continue

                symbol = Symbol(sym.name, sym_type, sym_size, loc)
                if sym_type == SymbolType.OBJECT:
                    symbol.add_range((Addr(loc), Addr(loc + sym_size)))
                self.symbols[sym.name] = symbol
        log.debug(f"Loaded {len(self.symbols)} symbols from ELF header")

    def _dwarf_subprogram(self, die: DIE):
        """
        Load subprogram entries from DWARF and extend the ELF symbols with its info.
        """
        if "DW_AT_name" not in die.attributes:
            return

        name = die.attributes["DW_AT_name"].value.decode("utf8")
        if name not in self.symbols:
            log.debug(f"There is dwarf info for {name} but no ELF entry")
            return
        symbol: Symbol = self.symbols[name]

        if "DW_AT_ranges" in die.attributes:
            # Function with ranges
            range = die.attributes["DW_AT_ranges"].value
            print(range)
            raise ValueError(
                "Ranges not yet handled. PLEASE IMPLEMENT or comment out :("
            )
        elif "DW_AT_low_pc" in die.attributes:
            # Continuous function
            low_pc = die.attributes["DW_AT_low_pc"].value
            high_pc_attr = die.attributes["DW_AT_high_pc"]
            high_pc_attr_class = describe_form_class(high_pc_attr.form)

            # DWARF v4 in section 2.17 describes how to interpret the
            # DW_AT_high_pc attribute based on the class of its form.
            # For class 'address' it's taken as an absolute address
            # (similarly to DW_AT_low_pc); for class 'constant', it's
            # an offset from DW_AT_low_pc.
            if high_pc_attr_class == "address":
                high_pc = high_pc_attr.value
            elif high_pc_attr_class == "constant":
                high_pc = low_pc + high_pc_attr.value
            else:
                log.error("Error: invalid DW_AT_high_pc class:", high_pc_attr_class)
                return
            symbol.add_range((Addr(low_pc), Addr(high_pc)))
            symbol.add_entry_point(Addr(low_pc))

    def _add_dwarf_symbols_data(self):
        """
        Load DWARF info for symbols and calls
        """
        if not self.debug_info:
            return

        for cu in self.debug_info.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    self._dwarf_subprogram(die)

    def _clean_up_symbols(self):
        """
        Remove all symbols which don't have a range assigned.
        Also adds missing entry points to functions.
        """
        cleaned_syms = dict()
        for key, sym in self.symbols.items():
            if len(sym.ranges) == 0:
                # Drop symbols without ranges
                continue
            if len(sym.entry_points) == 0:
                # Assume first range block is the entry point
                sym.add_entry_point(sym.ranges[0][0])
            cleaned_syms[key] = sym
        log.debug(
            f"Dropped {len(self.symbols) - len(cleaned_syms)} symbols having no size."
        )
        self.symbols = cleaned_syms

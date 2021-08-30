#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2020-2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

import argparse
import os
import sys

import yaml

CMDDESCS_C_TEMPLATE = """// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
//
// WARNING: This file was auto-generated by cmd_descs_generate.py script. Do not
// modify it manually. Look at cmd_descs.yaml if you want to update commands.
//

#include <cmd_descs.h>

{helps_declarations}

{helps}
RZ_IPI void rzshell_cmddescs_init(RzCore *core) {{
\tRzCmdDesc *root_cd = rz_cmd_get_root(core->rcmd);
\trz_cmd_batch_start(core->rcmd);
{init_code}
\trz_cmd_batch_end(core->rcmd);
}}
"""

CMDDESCS_H_TEMPLATE = """// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
//
// WARNING: This file was auto-generated by cmd_descs_generate.py script. Do not
// modify it manually. Look at cmd_descs.yaml if you want to update commands.
//

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_util.h>

// Command handlers, manually defined somewhere else
{handlers_declarations}

// Main function that initialize the entire commands tree
RZ_IPI void rzshell_cmddescs_init(RzCore *core);
"""

DESC_HELP_DETAIL_ENTRY_TEMPLATE = (
    """\t{{ .text = {text}, .arg_str = {arg_str}, .comment = {comment} }}"""
)
DESC_HELP_DETAIL_ENTRIES_TEMPLATE = """static const RzCmdDescDetailEntry {cname}[] = {{
{entry}
}};
"""

DESC_HELP_DETAIL_TEMPLATE = """\t{{ .name = {name}, .entries = {entries} }}"""
DESC_HELP_DETAILS_TEMPLATE = """static const RzCmdDescDetail {cname}[] = {{
{details}
}};
"""
DECL_DESC_HELP_DETAILS_TEMPLATE = "static const RzCmdDescDetail {cname}[{size}];"

DESC_HELP_ARG_CHOICES = "static const char *{cname}[] = {{ {choices} }};\n"
DESC_HELP_ARG_UNION_CHOICES = "\t\t.choices = {choices},\n"
DESC_HELP_ARG_TEMPLATE_FLAGS = "\t\t.flags = {flags},\n"
DESC_HELP_ARG_TEMPLATE_OPTIONAL = "\t\t.optional = {optional},\n"
DESC_HELP_ARG_TEMPLATE_NO_SPACE = "\t\t.no_space = {no_space},\n"
DESC_HELP_ARG_TEMPLATE_DEFAULT_VALUE = "\t\t.default_value = {default_value},\n"
DESC_HELP_ARG_TEMPLATE = """\t{{
\t\t.name = {name},
\t\t.type = {type},
{flags}{optional}{no_space}{default_value}{union}
\t}}"""
DESC_HELP_ARGS_TEMPLATE = """static const RzCmdDescArg {cname}[] = {{
{args}
}};
"""
DECL_DESC_HELP_ARGS_TEMPLATE = "static const RzCmdDescArg {cname}[{size}];"

DESC_HELP_TEMPLATE_DESCRIPTION = "\t.description = {description},\n"
DESC_HELP_TEMPLATE_ARGS_STR = "\t.args_str = {args_str},\n"
DESC_HELP_TEMPLATE_USAGE = "\t.usage = {usage},\n"
DESC_HELP_TEMPLATE_OPTIONS = "\t.options = {options},\n"
DESC_HELP_TEMPLATE_DETAILS = "\t.details = {details},\n"
DESC_HELP_TEMPLATE_ARGS = "\t.args = {args},\n"
DESC_HELP_TEMPLATE = """static const RzCmdDescHelp {cname} = {{
\t.summary = {summary},
{description}{args_str}{usage}{options}{details}{args}}};
"""

DEFINE_OLDINPUT_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_oldinput_new(core->rcmd, {parent_cname}_cd, {name}, {handler_cname}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_ARGV_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_argv_new(core->rcmd, {parent_cname}_cd, {name}, {handler_cname}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_ARGV_MODES_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_argv_modes_new(core->rcmd, {parent_cname}_cd, {name}, {modes}, {handler_cname}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_ARGV_STATE_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_argv_state_new(core->rcmd, {parent_cname}_cd, {name}, {modes}, {handler_cname}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_GROUP_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_group_new(core->rcmd, {parent_cname}_cd, {name}, {handler_cname}, {help_cname_ref}, &{group_help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_GROUP_MODES_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_group_modes_new(core->rcmd, {parent_cname}_cd, {name}, {modes}, {handler_cname}, {help_cname_ref}, &{group_help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_GROUP_STATE_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_group_state_new(core->rcmd, {parent_cname}_cd, {name}, {modes}, {handler_cname}, {help_cname_ref}, &{group_help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_INNER_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_inner_new(core->rcmd, {parent_cname}_cd, {name}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""
DEFINE_FAKE_TEMPLATE = """
\tRzCmdDesc *{cname}_cd = rz_cmd_desc_fake_new(core->rcmd, {parent_cname}_cd, {name}, &{help_cname});
\trz_warn_if_fail({cname}_cd);"""

SET_DEFAULT_MODE_TEMPLATE = """
\trz_cmd_desc_set_default_mode({cname}_cd, {default_mode});"""

CD_TYPE_OLDINPUT = "RZ_CMD_DESC_TYPE_OLDINPUT"
CD_TYPE_GROUP = "RZ_CMD_DESC_TYPE_GROUP"
CD_TYPE_ARGV = "RZ_CMD_DESC_TYPE_ARGV"
CD_TYPE_ARGV_MODES = "RZ_CMD_DESC_TYPE_ARGV_MODES"
CD_TYPE_ARGV_STATE = "RZ_CMD_DESC_TYPE_ARGV_STATE"
CD_TYPE_FAKE = "RZ_CMD_DESC_TYPE_FAKE"
CD_TYPE_INNER = "RZ_CMD_DESC_TYPE_INNER"

CD_VALID_TYPES = [
    CD_TYPE_OLDINPUT,
    CD_TYPE_GROUP,
    CD_TYPE_ARGV,
    CD_TYPE_ARGV_MODES,
    CD_TYPE_ARGV_STATE,
    CD_TYPE_FAKE,
    CD_TYPE_INNER,
]

CD_ARG_LAST_TYPES = [
    "RZ_CMD_ARG_TYPE_RZNUM",
    "RZ_CMD_ARG_TYPE_STRING",
    "RZ_CMD_ARG_TYPE_CMD",
]


def escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def strornull(s):
    return '"' + escape(s) + '"' if s is not None else "NULL"


def strip(s):
    return s.strip("\n") if s is not None else None


def compute_cname(name):
    if name == "":
        return "empty"

    name = name.translate(
        str.maketrans(
            {
                ".": "_dot_",
                "*": "_star_",
                ">": "_greater_",
                "<": "_minor_",
                "-": "_minus_",
                "+": "_plus_",
                "=": "_equal_",
                "$": "_dollar_",
                "?": "_question_",
                "/": "_slash_",
                "\\": "_backslash_",
                "&": "_and_",
                "!": "_escl_",
                "#": "_hash_",
                " ": "_space_",
                "(": "_oparen_",
                ")": "_cparen_",
            }
        )
    )
    if name.startswith("_"):
        name = name[1:]

    return name


def flat(l):
    if l is None:
        return []
    if not isinstance(l, list):
        return [l]

    out = []
    for i in l:
        out += flat(i)
    return out


class Arg:
    def __init__(self, cd, c):
        if "name" not in c or "type" not in c:
            print("Argument of %s should have `name`/`type` fields" % (cd.name,))
            sys.exit(1)

        self.cd = cd
        # RzCmdDescArg fields
        self.name = c.pop("name")
        self.flags = c.pop("flags", None)
        self.optional = c.pop("optional", None)
        self.no_space = c.pop("no_space", None)
        self.type = c.pop("type")
        self.default_value = (
            str(c.pop("default_value")) if "default_value" in c else None
        )
        self.choices = c.pop("choices", None)
        if c.keys():
            print(
                "Argument %s for command %s has unrecognized properties: %s."
                % (self.name, self.cd.name, c.keys())
            )
            sys.exit(1)

        if self.default_value is not None and self.optional is not None:
            print(
                "Argument %s for command %s has both optional and default_value."
                % (self.name, self.cd.name)
            )
            sys.exit(1)

    def _get_choices_cname(self):
        if self.type == "RZ_CMD_ARG_TYPE_CHOICES":
            return self.cd.cname + "_" + compute_cname(self.name) + "_choices"

        raise Exception("_get_choices_cname should be called on ARG_TYPE_CHOICES only")

    def _get_union(self):
        if self.type == "RZ_CMD_ARG_TYPE_CHOICES":
            return DESC_HELP_ARG_UNION_CHOICES.format(choices=self._get_choices_cname())
        return ""

    def __str__(self):
        flags = (
            DESC_HELP_ARG_TEMPLATE_FLAGS.format(flags=self.flags)
            if self.flags is not None and self.flags != ""
            else ""
        )
        optional = (
            DESC_HELP_ARG_TEMPLATE_OPTIONAL.format(
                optional="true" if self.optional else "false"
            )
            if self.optional is not None
            else ""
        )
        no_space = (
            DESC_HELP_ARG_TEMPLATE_NO_SPACE.format(
                no_space="true" if self.no_space else "false"
            )
            if self.no_space is not None
            else ""
        )
        default_value = (
            DESC_HELP_ARG_TEMPLATE_DEFAULT_VALUE.format(
                default_value=strornull(self.default_value)
            )
            if self.default_value is not None
            else ""
        )
        return DESC_HELP_ARG_TEMPLATE.format(
            name=strornull(self.name),
            type=self.type,
            flags=flags,
            optional=optional,
            no_space=no_space,
            default_value=default_value,
            union=self._get_union(),
        )

    def get_cstructure(self):
        if self.type == "RZ_CMD_ARG_TYPE_CHOICES":
            return DESC_HELP_ARG_CHOICES.format(
                cname=self._get_choices_cname(),
                choices=", ".join(
                    [
                        '"%s"' % (x,) if x != "NULL" else x
                        for x in self.choices + ["NULL"]
                    ]
                ),
            )
        return ""


def format_detail_entry(c):
    if "text" not in c or "comment" not in c:
        print("No `text`/`comment` fields for DetailEntry %s" % (c,))
        sys.exit(1)

    text = strip(c["text"])
    comment = strip(c["comment"])
    arg_str = strip(c.get("arg_str"))

    return DESC_HELP_DETAIL_ENTRY_TEMPLATE.format(
        text=strornull(text),
        arg_str=strornull(arg_str),
        comment=strornull(comment),
    )


class Detail:
    def __init__(self, cd, c):
        if "name" not in c or "entries" not in c:
            print("No `name`/`entries` fields for Detail %s" % (c,))
            sys.exit(1)

        self.cd = cd
        # RzCmdDescDetail fields
        self.name = strip(c.pop("name"))
        self.entries = [format_detail_entry(x) for x in c.pop("entries")]
        if c.keys():
            print(
                "Detail %s for command %s has unrecognized properties: %s."
                % (self.name, self.cd.name, c.keys())
            )
            sys.exit(1)

    def get_detail_entries_cname(self):
        return self.cd.cname + "_" + compute_cname(self.name) + "_detail_entries"

    def __str__(self):
        return DESC_HELP_DETAIL_TEMPLATE.format(
            name=strornull(self.name),
            entries=self.get_detail_entries_cname(),
        )

    def get_cstructure(self):
        return DESC_HELP_DETAIL_ENTRIES_TEMPLATE.format(
            cname=self.get_detail_entries_cname(),
            entry=",\n".join([str(e) for e in self.entries] + ["\t{ 0 },"]),
        )


class CmdDesc:
    c_cds = {}
    c_handlers = {}
    c_args = {}
    c_details = {}

    def _process_details(self, c):
        if "details" in c and isinstance(c["details"], list):
            self.details = [Detail(self, x) for x in c.pop("details", [])]
        elif "details" in c and isinstance(c["details"], str):
            self.details_alias = c.pop("details")

    def _process_args(self, c):
        if "args" in c and isinstance(c["args"], list):
            self.args = [Arg(self, x) for x in c.pop("args", [])]
            if (
                self.args
                and self.args[-1].type in CD_ARG_LAST_TYPES
                and self.args[-1].flags is None
            ):
                self.args[-1].flags = "RZ_CMD_ARG_FLAG_LAST"
        elif "args" in c and isinstance(c["args"], str):
            self.args_alias = c.pop("args")

    def _set_type(self, c):
        if "type" in c:
            self.type = c.pop("type")
        elif c.get("subcommands"):
            self.type = CD_TYPE_GROUP
        elif self.modes:
            self.type = CD_TYPE_ARGV_MODES
        else:
            self.type = CD_TYPE_ARGV

    def _set_subcommands(self, c, yamls):
        if "subcommands" in c and isinstance(c["subcommands"], list):
            # The list of subcommands is embedded in the current file
            self.subcommands = [
                CmdDesc(yamls, x, self, i)
                for i, x in enumerate(c.pop("subcommands", []))
            ]
        elif "subcommands" in c and isinstance(c["subcommands"], str):
            # The list of subcommands is in another file
            subcommands_name = c.pop("subcommands")
            if subcommands_name not in yamls:
                print(
                    "Command %s referenced another YAML file (%s) that is not passed as arg to cmd_descs_generate.py."
                    % (self.name, subcommands_name)
                )
                sys.exit(1)

            external_c = yamls[subcommands_name]
            self.subcommands = [
                CmdDesc(yamls, x, self, i) for i, x in enumerate(external_c)
            ]

        # handle the exec_cd, which is a cd that has the same name as its parent
        if (
            self.subcommands
            and self.subcommands[0].name == self.name
            and self.subcommands[0].type not in [CD_TYPE_INNER, CD_TYPE_FAKE]
        ):
            self.exec_cd = self.subcommands[0]

    def __init__(self, yamls, c, parent=None, pos=0):
        self.pos = pos

        if not c:
            # used only for root node
            self.name = ""
            self.cname = "root"
            self.summary = ""
            self.type = CD_TYPE_GROUP
            return

        if not c.get("name") or not c.get("summary"):
            print("No `name`/`summary` fields in", c)
            sys.exit(1)

        # RzCmdDesc fields
        self.name = c.pop("name")
        self.cname = c.pop("cname", None) or compute_cname(self.name)
        self.type = None
        self.parent = parent
        self.subcommands = None
        self.exec_cd = None
        self.modes = c.pop("modes", None)
        self.handler = c.pop("handler", None)
        self.default_mode = c.pop("default_mode", None)
        # RzCmdDescHelp fields
        self.summary = strip(c.pop("summary"))
        self.description = strip(c.pop("description", None))
        self.args_str = strip(c.pop("args_str", None))
        self.usage = strip(c.pop("usage", None))
        self.options = strip(c.pop("options", None))

        self.details = None
        self.details_alias = None
        self._process_details(c)

        self.args = None
        self.args_alias = None
        self._process_args(c)

        # determine type before parsing subcommands, so children can check type of parent
        self._set_type(c)

        self._set_subcommands(c, yamls)

        self._validate(c)
        CmdDesc.c_cds[self.cname] = self
        if self.get_handler_cname():
            CmdDesc.c_handlers[self.get_handler_cname()] = self
        if self.args:
            CmdDesc.c_args[CmdDesc.get_arg_cname(self)] = self
        if self.details:
            CmdDesc.c_details[CmdDesc.get_detail_cname(self)] = self

    def _validate(self, c):
        if c.keys():
            print("Command %s has unrecognized properties: %s." % (self.name, c.keys()))
            sys.exit(1)

        if self.type not in CD_VALID_TYPES:
            print("Command %s does not have a valid type." % (self.name,))
            sys.exit(1)

        if (
            self.type
            in [CD_TYPE_ARGV, CD_TYPE_ARGV_MODES, CD_TYPE_ARGV_STATE, CD_TYPE_OLDINPUT]
            and not self.cname
        ):
            print("Command %s does not have cname field" % (self.name,))
            sys.exit(1)

        if (
            self.parent
            and self.parent.name == self.name
            and self.pos != 0
            and self.type not in [CD_TYPE_INNER, CD_TYPE_FAKE]
        ):
            print(
                "If a command has the same name as its parent, it can only be the first child. See parent of Command %s"
                % (self.cname,)
            )
            sys.exit(1)

        if self.parent and self.parent.type not in [
            CD_TYPE_GROUP,
            CD_TYPE_INNER,
            CD_TYPE_OLDINPUT,
        ]:
            print("The parent of %s is of the wrong type" % (self.cname,))
            sys.exit(1)

        if self.cname in CmdDesc.c_cds:
            print("Another command already has the same cname as %s" % (self.cname,))
            sys.exit(1)

        if (
            self.type in [CD_TYPE_ARGV, CD_TYPE_ARGV_MODES, CD_TYPE_ARGV_STATE]
            and self.args is None
            and self.args_alias is None
        ):
            print("Specify arguments for command %s" % (self.name,))
            sys.exit(1)

    def get_handler_cname(self):
        if self.type in [CD_TYPE_ARGV, CD_TYPE_ARGV_MODES, CD_TYPE_ARGV_STATE]:
            return "rz_" + (self.handler or self.cname) + "_handler"

        if self.type == CD_TYPE_OLDINPUT:
            return "rz_" + (self.handler or self.cname)

        return None

    @classmethod
    def get_arg_cname(cls, cd):
        return cd.cname + "_args"

    @classmethod
    def get_detail_cname(cls, cd):
        return cd.cname + "_details"

    def get_help_cname(self):
        return self.cname + "_help"

    def __str__(self):
        out = ""
        details_cname = None
        args_cname = None

        if self.details is not None:
            out += "\n".join([d.get_cstructure() for d in self.details])
            out += DESC_HELP_DETAILS_TEMPLATE.format(
                cname=CmdDesc.get_detail_cname(self),
                details=",\n".join([str(d) for d in self.details] + ["\t{ 0 },"]),
            )
            details_cname = CmdDesc.get_detail_cname(self)
        elif self.details_alias is not None:
            details_cname = self.details_alias + "_details"

        if self.args is not None:
            out += "\n".join(
                [a.get_cstructure() for a in self.args if a.get_cstructure() != ""]
            )
            out += DESC_HELP_ARGS_TEMPLATE.format(
                cname=CmdDesc.get_arg_cname(self),
                args=",\n".join([str(a) for a in self.args] + ["\t{ 0 },"]),
            )
            args_cname = CmdDesc.get_arg_cname(self)
        elif self.args_alias is not None:
            args_cname = self.args_alias + "_args"

        description = (
            DESC_HELP_TEMPLATE_DESCRIPTION.format(
                description=strornull(self.description)
            )
            if self.description is not None
            else ""
        )
        args_str = (
            DESC_HELP_TEMPLATE_ARGS_STR.format(args_str=strornull(self.args_str))
            if self.args_str is not None
            else ""
        )
        usage = (
            DESC_HELP_TEMPLATE_USAGE.format(usage=strornull(self.usage))
            if self.usage is not None
            else ""
        )
        options = (
            DESC_HELP_TEMPLATE_OPTIONS.format(options=strornull(self.options))
            if self.options is not None
            else ""
        )
        details = (
            DESC_HELP_TEMPLATE_DETAILS.format(details=details_cname)
            if details_cname is not None
            else ""
        )
        arguments = (
            DESC_HELP_TEMPLATE_ARGS.format(args=args_cname)
            if args_cname is not None
            else ""
        )
        out += DESC_HELP_TEMPLATE.format(
            cname=self.get_help_cname(),
            summary=strornull(self.summary),
            description=description,
            args_str=args_str,
            usage=usage,
            options=options,
            details=details,
            args=arguments,
        )

        if self.subcommands:
            out += "\n".join([str(child) for child in self.subcommands])
        return out

    def str_tab(self, tab=0):
        spaces = " " * tab
        out = ""
        out += spaces + "Name: %s\n" % (self.name,)
        out += spaces + "CName: %s\n" % (self.cname,)
        out += spaces + "Summary: %s\n" % (self.summary,)
        if self.description:
            out += spaces + "Description: %s\n" % (self.description,)
        if self.subcommands:
            out += spaces + "Subcommands:\n"
            for c in self.subcommands:
                out += c.str_tab(tab + 4)
                out += "\n"

        return out

    def __repr__(self):
        return self.str_tab()


def createcd_typegroup(cd):
    if cd.exec_cd and cd.exec_cd.type == CD_TYPE_ARGV_MODES:
        formatted_string = DEFINE_GROUP_MODES_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            modes=" | ".join(cd.exec_cd.modes),
            handler_cname=cd.exec_cd.get_handler_cname(),
            help_cname_ref="&" + cd.exec_cd.get_help_cname(),
            group_help_cname=cd.get_help_cname(),
        )
        if cd.exec_cd.default_mode is not None:
            formatted_string += SET_DEFAULT_MODE_TEMPLATE.format(
                cname=cd.cname,
                default_mode=cd.exec_cd.default_mode,
            )
        formatted_string += "\n".join(
            [createcd(child) for child in cd.subcommands[1:] or []]
        )
    elif cd.exec_cd and cd.exec_cd.type == CD_TYPE_ARGV_STATE:
        formatted_string = DEFINE_GROUP_STATE_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            modes=" | ".join(cd.exec_cd.modes),
            handler_cname=cd.exec_cd.get_handler_cname(),
            help_cname_ref="&" + cd.exec_cd.get_help_cname(),
            group_help_cname=cd.get_help_cname(),
        )
        if cd.exec_cd.default_mode is not None:
            formatted_string += SET_DEFAULT_MODE_TEMPLATE.format(
                cname=cd.cname,
                default_mode=cd.exec_cd.default_mode,
            )
        formatted_string += "\n".join(
            [createcd(child) for child in cd.subcommands[1:] or []]
        )
    else:
        formatted_string = DEFINE_GROUP_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            handler_cname=(cd.exec_cd and cd.exec_cd.get_handler_cname()) or "NULL",
            help_cname_ref=(cd.exec_cd and "&" + cd.exec_cd.get_help_cname()) or "NULL",
            group_help_cname=cd.get_help_cname(),
        )
        subcommands = (
            cd.exec_cd and cd.subcommands and cd.subcommands[1:]
        ) or cd.subcommands
        formatted_string += "\n".join([createcd(child) for child in subcommands or []])

    return formatted_string


def createcd(cd):
    formatted_string = None

    if cd.type == CD_TYPE_ARGV:
        formatted_string = DEFINE_ARGV_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            handler_cname=cd.get_handler_cname(),
            help_cname=cd.get_help_cname(),
        )
    elif cd.type == CD_TYPE_ARGV_MODES:
        formatted_string = DEFINE_ARGV_MODES_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            modes=" | ".join(cd.modes),
            handler_cname=cd.get_handler_cname(),
            help_cname=cd.get_help_cname(),
        )
        if cd.default_mode is not None:
            formatted_string += SET_DEFAULT_MODE_TEMPLATE.format(
                cname=cd.cname,
                default_mode=cd.default_mode,
            )
    elif cd.type == CD_TYPE_ARGV_STATE:
        formatted_string = DEFINE_ARGV_STATE_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            modes=" | ".join(cd.modes),
            handler_cname=cd.get_handler_cname(),
            help_cname=cd.get_help_cname(),
        )
        if cd.default_mode is not None:
            formatted_string += SET_DEFAULT_MODE_TEMPLATE.format(
                cname=cd.cname,
                default_mode=cd.default_mode,
            )
    elif cd.type == CD_TYPE_FAKE:
        formatted_string = DEFINE_FAKE_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            help_cname=cd.get_help_cname(),
        )
    elif cd.type == CD_TYPE_INNER:
        formatted_string = DEFINE_INNER_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            help_cname=cd.get_help_cname(),
        )
        formatted_string += "\n".join(
            [createcd(child) for child in cd.subcommands or []]
        )
    elif cd.type == CD_TYPE_OLDINPUT:
        formatted_string = DEFINE_OLDINPUT_TEMPLATE.format(
            cname=cd.cname,
            parent_cname=cd.parent.cname,
            name=strornull(cd.name),
            handler_cname=cd.get_handler_cname(),
            help_cname=cd.get_help_cname(),
        )
        formatted_string += "\n".join(
            [createcd(child) for child in cd.subcommands or []]
        )
    elif cd.type == CD_TYPE_GROUP:
        formatted_string = createcd_typegroup(cd)
    else:
        raise Exception("Not handled cd type")

    return formatted_string


def arg2decl(cd):
    return DECL_DESC_HELP_ARGS_TEMPLATE.format(
        cname=CmdDesc.get_arg_cname(cd), size=len(cd.args) + 1
    )


def detail2decl(cd):
    return DECL_DESC_HELP_DETAILS_TEMPLATE.format(
        cname=CmdDesc.get_detail_cname(cd), size=len(cd.details) + 1
    )


def handler2decl(cd_type, handler_name):
    if cd_type == CD_TYPE_ARGV:
        return "RZ_IPI RzCmdStatus %s(RzCore *core, int argc, const char **argv);" % (
            handler_name,
        )
    if cd_type == CD_TYPE_ARGV_MODES:
        return (
            "RZ_IPI RzCmdStatus %s(RzCore *core, int argc, const char **argv, RzOutputMode mode);"
            % (handler_name,)
        )
    if cd_type == CD_TYPE_ARGV_STATE:
        return (
            "RZ_IPI RzCmdStatus %s(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state);"
            % (handler_name,)
        )
    if cd_type == CD_TYPE_OLDINPUT:
        return "RZ_IPI int %s(void *data, const char *input);" % (handler_name,)

    return None


parser = argparse.ArgumentParser(
    description="Generate .c/.h files from Command Descriptors YAML file."
)
parser.add_argument(
    "--src-output-dir", type=str, required=False, help="Source output directory"
)
parser.add_argument("--output-dir", type=str, required=True, help="Output directory")
parser.add_argument(
    "yaml_files",
    type=argparse.FileType("r"),
    nargs="+",
    help="Input YAML files containing commands descriptions. One should be named 'root'.",
)

args = parser.parse_args()

commands_yml_arr = [yaml.safe_load(f) for f in args.yaml_files]
commands_yml = {c["name"]: c["commands"] for c in commands_yml_arr}

root_cd = CmdDesc(commands_yml, None)
root_cds = [CmdDesc(commands_yml, c, root_cd) for c in commands_yml["root"]]

arg_decls = [arg2decl(cd) for cd in CmdDesc.c_args.values()]
detail_decls = [detail2decl(cd) for cd in CmdDesc.c_details.values()]
helps = [str(cd) for cd in root_cds]
init_code = [createcd(cd) for cd in root_cds]

cf_text = CMDDESCS_C_TEMPLATE.format(
    helps_declarations="\n".join(detail_decls + arg_decls),
    helps="\n".join(helps),
    init_code="\n".join(init_code),
)
with open(os.path.join(args.output_dir, "cmd_descs.c"), "w", encoding="utf8") as f:
    f.write(cf_text)
if args.src_output_dir:
    with open(
        os.path.join(args.src_output_dir, "cmd_descs.c"), "w", encoding="utf8"
    ) as f:
        f.write(cf_text)

handlers_decls = filter(
    lambda th: th[1] is not None,
    [(cd.type, cd.get_handler_cname()) for cd in CmdDesc.c_cds.values()],
)

hf_text = CMDDESCS_H_TEMPLATE.format(
    handlers_declarations="\n".join([handler2decl(t, h) for t, h in handlers_decls]),
)
with open(os.path.join(args.output_dir, "cmd_descs.h"), "w", encoding="utf8") as f:
    f.write(hf_text)
if args.src_output_dir:
    with open(
        os.path.join(args.src_output_dir, "cmd_descs.h"), "w", encoding="utf8"
    ) as f:
        f.write(hf_text)

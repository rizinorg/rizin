#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2020-2021 ret2libc <sirmy15@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

CD_TYPE_GROUP = "RZ_CMD_DESC_TYPE_GROUP"
CD_TYPE_ARGV = "RZ_CMD_DESC_TYPE_ARGV"
CD_TYPE_ARGV_MODES = "RZ_CMD_DESC_TYPE_ARGV_MODES"
CD_TYPE_ARGV_STATE = "RZ_CMD_DESC_TYPE_ARGV_STATE"
CD_TYPE_FAKE = "RZ_CMD_DESC_TYPE_FAKE"
CD_TYPE_INNER = "RZ_CMD_DESC_TYPE_INNER"

CD_VALID_TYPES = [
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
                "%": "_perc_",
            }
        )
    )
    if name.startswith("_"):
        name = name[1:]

    return name


def get_handler_cname(handler, cname):
    return "rz_" + (handler or cname) + "_handler"

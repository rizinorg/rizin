<!-- SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re> -->
<!-- SPDX-License-Identifier: LGPL-3.0-only -->

# RzInquiry

This module implements novel analysis approaches based on RzIL. It is meant as
an intermediate ground to implement and evaluate new ideas.
Everything in this module should be considered experimental and subject
to change.

## Architecture overview

```
                                                                 Interpret IL Ops
                                                                 until fixed point
                                                                  ┌─────────────┐
                                                                  │             ▼       Dispatch Pure eval  ┌──────────────┐
                        ┌────────┐ spwans        ┌──────────────┐ │        ┌───────────┐to value domain     │ Value Domain │
                        │        ├──────────────►│              ├─┘        │Interpret  ├──────────────────► │ (Constant,   │
                        │        │◄──────────────┤ Interpreter  │          │IL Op      │◄───────────────────┤  Stack/Heap) │
                        │        │  Req. IL ops  │              │◄┐        └────┬──────┘ Return interpreted │  Ptr/NoPtr)  │
                        │        │               └──────────────┘ │             │        Value              └──────────────┘
                        │        │                                └─────────────┘
             Req IL Op  │        │ spawns        ┌──────────────┐
┌──────────┐ at addr    │        ┼──────────────►│              │
│ IL       │◄───────────┤Driver  │◄──────────────┤ Interpreter  │  ...
│ Cache    ├───────────►│        │  Req. IL ops  │              │
└──────────┘ Lift and   │        │               └──────────────┘
             return     │        │
                        │        │ spawns        ┌──────────────┐
                        │        ├──────────────►│              │
                        │        │◄──────────────┤ Interpreter  │ ...
                        │        │  Req. IL ops  │              │
                        │        │               └──────────────┘
                        │        │
                        └────────┘
```

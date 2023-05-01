// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Defines the various reigster types supported by the PIC16F family
 * and a lookup table to map from these register types to their string names.
 * */

#ifndef RZ_PIC_MIDRANGE_PIC_REGTYPES_H
#define RZ_PIC_MIDRANGE_PIC_REGTYPES_H

// clang-format off

/**
 * Instead of storing strings in file register map,
 * it's better to store enums in order to save memory.
 * */
typedef enum pic_midrange_reg_type_t {
    REG_INDF,
    REG_TMR0,
    REG_PCL, /* lower byte of PC register */
    REG_STATUS, /* status register */
    REG_FSR,
    REG_PORTA,
    REG_PORTB,
    REG_PORTC,
    REG_PORTD,
    REG_PORTE,
    REG_PORTF,
    REG_PORTG,
    REG_PCLATH, /* PCLATH is used to control PCH (higher part of PC reg)*/
    REG_INTCON,
    REG_PIR1,
    REG_PIR2,
    REG_TMR1L,
    REG_TMR1H,
    REG_T1CON,
    REG_TMR2,
    REG_T2CON,
    REG_SSPBUF,
    REG_SSPCON,
    REG_SSPCON2,
    REG_CCPR1L,
    REG_CCPR1H,
    REG_CCP1CON,
    REG_RCSTA,
    REG_TXREG,
    REG_RCREG,
    REG_CCPR2L,
    REG_CCPR2H,
    REG_CCP2CON,
    REG_ADRESH,
    REG_ADRESL,
    REG_ADCON0,
    REG_ADCON,
    REG_OPTION_REG,
    REG_TRISA,
    REG_TRISB,
    REG_TRISC,
    REG_TRISD,
    REG_TRISE,
    REG_TRISF,
    REG_TRISG,
    REG_PIE1,
    REG_PIE2,
    REG_PCON,
    REG_OSCCON,
    REG_OSCCAL,
    REG_PR2,
    REG_SSPADD,
    REG_SSPSTAT,
    REG_TXSTA,
    REG_SPBRG,
    REG_SPBRGH,
    REG_ADDCON1,
    REG_OSCTUNE,
    REG_WPUB,
    REG_IOCB,
    REG_VRCON,
    REG_PWM1CON,
    REG_ECCPAS,
    REG_PSTRCON,
    REG_ADCON1,
    REG_WDTCON,
    REG_CM1CON0,
    REG_CM2CON0,
    REG_CM2CON1,
    REG_EEDAT,
    REG_EEADR,
    REG_EEDATH,
    REG_EEADRH,
    REG_SRCON,
    REG_BAUDCTL,
    REG_ANSEL,
    REG_ANSELH,
    REG_EECON1,
    REG_EECON2,
    REG_RESERVED,
    REG_FREG, /* normal indexed file register */
    REG_UNIMPLEMENTED, /* unimplemented registers are read as 0 */
    REG_NUM /* can be used when a function fails and want to return an invalid value */
} PicMidrangeRegType;

/**
 * Map from reg enums to reg names
 * */
const char* pic_midrange_il_regnames[REG_UNIMPLEMENTED + 1] = {
    [REG_INDF]          = "REG_INDF",
    [REG_TMR0]          = "REG_TMR0",
    [REG_PCL]           = "REG_PCL",
    [REG_STATUS]        = "REG_STATUS",
    [REG_FSR]           = "REG_FSR",
    [REG_PORTA]         = "REG_PORTA",
    [REG_PORTB]         = "REG_PORTB",
    [REG_PORTC]         = "REG_PORTC",
    [REG_PORTD]         = "REG_PORTD",
    [REG_PORTE]         = "REG_PORTE",
    [REG_PORTF]         = "REG_PORTF",
    [REG_PORTG]         = "REG_PORTG",
    [REG_PCLATH]        = "REG_PCLATH",
    [REG_INTCON]        = "REG_INTCON",
    [REG_PIR1]          = "REG_PIR1",
    [REG_PIR2]          = "REG_PIR2",
    [REG_TMR1L]         = "REG_TMR1L",
    [REG_TMR1H]         = "REG_TMR1H",
    [REG_T1CON]         = "REG_T1CON",
    [REG_TMR2]          = "REG_TMR2",
    [REG_T2CON]         = "REG_T2CON",
    [REG_SSPBUF]        = "REG_SSPBUF",
    [REG_SSPCON]        = "REG_SSPCON",
    [REG_SSPCON2]       = "REG_SSPCON2",
    [REG_CCPR1L]        = "REG_CCPR1L",
    [REG_CCPR1H]        = "REG_CCPR1H",
    [REG_CCP1CON]       = "REG_CCP1CON",
    [REG_RCSTA]         = "REG_RCSTA",
    [REG_TXREG]         = "REG_TXREG",
    [REG_RCREG]         = "REG_RCREG",
    [REG_CCPR2L]        = "REG_CCPR2L",
    [REG_CCPR2H]        = "REG_CCPR2H",
    [REG_CCP2CON]       = "REG_CCP2CON",
    [REG_ADRESH]        = "REG_ADRESH",
    [REG_ADRESL]        = "REG_ADRESL",
    [REG_ADCON0]        = "REG_ADCON0",
    [REG_ADCON]         = "REG_ADCON",
    [REG_OPTION_REG]    = "REG_OPTION_REG",
    [REG_TRISA]         = "REG_TRISA",
    [REG_TRISB]         = "REG_TRISB",
    [REG_TRISC]         = "REG_TRISC",
    [REG_TRISD]         = "REG_TRISD",
    [REG_TRISE]         = "REG_TRISE",
    [REG_TRISF]         = "REG_TRISF",
    [REG_TRISG]         = "REG_TRISG",
    [REG_PIE1]          = "REG_PIE1",
    [REG_PIE2]          = "REG_PIE2",
    [REG_PCON]          = "REG_PCON",
    [REG_OSCCON]        = "REG_OSCCON",
    [REG_OSCCAL]        = "REG_OSCCAL",
    [REG_PR2]           = "REG_PR2",
    [REG_SSPADD]        = "REG_SSPADD",
    [REG_SSPSTAT]       = "REG_SSPSTAT",
    [REG_TXSTA]         = "REG_TXSTA",
    [REG_SPBRG]         = "REG_SPBRG",
    [REG_SPBRGH]        = "REG_SPBRGH",
    [REG_ADDCON1]       = "REG_ADDCON1",
    [REG_OSCTUNE]       = "REG_OSCTUNE",
    [REG_WPUB]          = "REG_WPUB",
    [REG_IOCB]          = "REG_IOCB",
    [REG_VRCON]         = "REG_VRCON",
    [REG_PWM1CON]       = "REG_PWM1CON",
    [REG_ECCPAS]        = "REG_ECCPAS",
    [REG_PSTRCON]       = "REG_PSTRCON",
    [REG_ADCON1]        = "REG_ADCON1",
    [REG_WDTCON]        = "REG_WDTCON",
    [REG_CM1CON0]       = "REG_CM1CON0",
    [REG_CM2CON0]       = "REG_CM2CON0",
    [REG_CM2CON1]       = "REG_CM2CON1",
    [REG_EEDAT]         = "REG_EEDAT",
    [REG_EEADR]         = "REG_EEADR",
    [REG_EEDATH]        = "REG_EEDATH",
    [REG_EEADRH]        = "REG_EEADRH",
    [REG_SRCON]         = "REG_SRCON",
    [REG_BAUDCTL]       = "REG_BAUDCTL",
    [REG_ANSEL]         = "REG_ANSEL",
    [REG_ANSELH]        = "REG_ANSELH",
    [REG_EECON1]        = "REG_EECON1",
    [REG_EECON2]        = "REG_EECON2",
    [REG_RESERVED]      = "REG_RESERVED",
    [REG_FREG]          = "REG_FREG",
    [REG_UNIMPLEMENTED] = "REG_UNIMPLEMENTED",
};

// clang-format on

#endif // RZ_PIC_MIDRANGE_PIC_REGTYPES_H

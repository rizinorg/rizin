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
    INDF,
    TMR0,
    PCL, /* lower byte of PC register */
    STATUS, /* status register */
    FSR,
    PORTA,
    PORTB,
    PORTC,
    PORTD,
    PORTE,
    PORTF,
    PORTG,
    PCLATH, /* PCLATH is used to control PCH (higher part of PC reg)*/
    INTCON,
    PIR1,
    PIR2,
    TMR1L,
    TMR1H,
    T1CON,
    TMR2,
    T2CON,
    SSPBUF,
    SSPCON,
    SSPCON2,
    CCPR1L,
    CCPR1H,
    CCP1CON,
    RCSTA,
    TXREG,
    RCREG,
    CCPR2L,
    CCPR2H,
    CCP2CON,
    ADRESH,
    ADRESL,
    ADCON0,

    ADCON,
    OPTION_REG,
    TRISA,
    TRISB,
    TRISC,
    TRISD,
    TRISE,
    TRISF,
    TRISG,
    PIE1,
    PIE2,
    PCON,
    OSCCON,
    OSCCAL,
    PR2,
    SSPADD,
    SSPSTAT,
    TXSTA,
    SPBRG,
    SPBRGH,
    ADDCON1,

    OSCTUNE,
    WPUB,
    IOCB,
    VRCON,
    PWM1CON,
    ECCPAS,
    PSTRCON,
    ADCON1,
    WDTCON,
    CM1CON0,
    CM2CON0,
    CM2CON1,
    EEDAT,
    EEADR,
    EEDATH,
    EEADRH,
    SRCON,
    BAUDCTL,
    ANSEL,
    ANSELH,
    EECON1,
    EECON2,
    _RESERVED,
    FREG, /* normal indexed file register */
    UNIMPLEMENTED, /* unimplemented registers are read as 0 */
    INVALID /* can be used when a function fails and want to return an invalid value */
} PicMidrangeRegType;

/**
 * Map from reg enums to reg names
 * */
const char* pic_midrange_regnames[] = {
    [INDF]          = "indf",
    [TMR0]          = "tmr0",
    [PCL]           = "pcl",
    [STATUS]        = "status",
    [FSR]           = "fsr",
    [PORTA]         = "porta",
    [PORTB]         = "portb",
    [PORTC]         = "portc",
    [PORTD]         = "portd",
    [PORTE]         = "porte",
    [PORTF]         = "portf",
    [PORTG]         = "portg",
    [PCLATH]        = "pclath",
    [INTCON]        = "intcon",
    [PIR1]          = "pir1",
    [PIR2]          = "pir2",
    [TMR1L]         = "tmr1l",
    [TMR1H]         = "tmr1h",
    [T1CON]         = "t1con",
    [TMR2]          = "tmr2",
    [T2CON]         = "t2con",
    [SSPBUF]        = "sspbuf",
    [SSPCON]        = "sspcon",
    [SSPCON2]       = "sspcon2",
    [CCPR1L]        = "ccpr1l",
    [CCPR1H]        = "ccpr1h",
    [CCP1CON]       = "ccp1con",
    [RCSTA]         = "rcsta",
    [TXREG]         = "txreg",
    [RCREG]         = "rcreg",
    [CCPR2L]        = "ccpr2l",
    [CCPR2H]        = "ccpr2h",
    [CCP2CON]       = "ccp2con",
    [ADRESH]        = "adresh",
    [ADRESL]        = "adresl",
    [ADCON0]        = "adcon0",
    [ADCON]         = "adcon",
    [OPTION_REG]    = "option_reg",
    [TRISA]         = "trisa",
    [TRISB]         = "trisb",
    [TRISC]         = "trisc",
    [TRISD]         = "trisd",
    [TRISE]         = "trise",
    [TRISF]         = "trisf",
    [TRISG]         = "trisg",
    [PIE1]          = "pie1",
    [PIE2]          = "pie2",
    [PCON]          = "pcon",
    [OSCCON]        = "osccon",
    [OSCCAL]        = "osccal",
    [PR2]           = "pr2",
    [SSPADD]        = "sspadd",
    [SSPSTAT]       = "sspstat",
    [TXSTA]         = "txsta",
    [SPBRG]         = "spbrg",
    [SPBRGH]        = "spbrgh",
    [ADDCON1]       = "addcon1",
    [OSCTUNE]       = "osctune",
    [WPUB]          = "wpub",
    [IOCB]          = "iocb",
    [VRCON]         = "vrcon",
    [PWM1CON]       = "pwm1con",
    [ECCPAS]        = "eccpas",
    [PSTRCON]       = "pstrcon",
    [ADCON1]        = "adcon1",
    [WDTCON]        = "wdtcon",
    [CM1CON0]       = "cm1con0",
    [CM2CON0]       = "cm2con0",
    [CM2CON1]       = "cm2con1",
    [EEDAT]         = "eedat",
    [EEADR]         = "eeadr",
    [EEDATH]        = "eedath",
    [EEADRH]        = "eeadrh",
    [SRCON]         = "srcon",
    [BAUDCTL]       = "baudctl",
    [ANSEL]         = "ansel",
    [ANSELH]        = "anselh",
    [EECON1]        = "eecon1",
    [EECON2]        = "eecon2",
    [_RESERVED]      = "reserved",
    [FREG]          = "freg",
    [UNIMPLEMENTED] = "unimplemented",
};
// clang-format on

static inline const char *pic_midrange_regname(ut32 reg) {
	if (reg >= RZ_ARRAY_SIZE(pic_midrange_regnames)) {
		rz_warn_if_reached();
		return NULL;
	}
	return pic_midrange_regnames[reg];
}

#endif // RZ_PIC_MIDRANGE_PIC_REGTYPES_H

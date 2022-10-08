// SPDX-FileCopyrightText: 2017-2018 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_X509_INTERNAL_H
#define RZ_X509_INTERNAL_H

RZ_IPI bool rz_x509_algorithmidentifier_parse(RX509AlgorithmIdentifier *ai, RASN1Object *object);
RZ_IPI void rz_x509_algorithmidentifier_fini(RX509AlgorithmIdentifier *ai);

RZ_IPI bool rz_x509_name_parse(RX509Name *name, RASN1Object *object);
RZ_IPI void rz_x509_name_fini(RX509Name *name);
RZ_IPI void rz_x509_name_dump(RX509Name *name, const char *pad, RzStrBuf *sb);
RZ_IPI void rz_x509_name_json(PJ *pj, RX509Name *name);

RZ_IPI void rz_x509_crl_free(RX509CertificateRevocationList *crl);
RZ_IPI void rz_x509_crlentry_dump(RX509CRLEntry *crle, const char *pad, RzStrBuf *sb);

#endif /* RZ_X509_INTERNAL_H */

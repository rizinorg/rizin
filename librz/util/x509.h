// SPDX-FileCopyrightText: 2017-2018 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_X509_INTERNAL_H
#define RZ_X509_INTERNAL_H

RZ_IPI bool rz_x509_algorithmidentifier_parse(RzX509AlgorithmIdentifier *ai, RzASN1Object *object);
RZ_IPI void rz_x509_algorithmidentifier_fini(RzX509AlgorithmIdentifier *ai);

RZ_IPI bool rz_x509_name_parse(RzX509Name *name, RzASN1Object *object);
RZ_IPI void rz_x509_name_fini(RzX509Name *name);
RZ_IPI void rz_x509_name_dump(RzX509Name *name, const char *pad, RzStrBuf *sb);
RZ_IPI void rz_x509_name_json(PJ *pj, RzX509Name *name);

RZ_IPI void rz_x509_crl_free(RzX509CertificateRevocationList *crl);
RZ_IPI void rz_x509_crlentry_dump(RzX509CRLEntry *crle, const char *pad, RzStrBuf *sb);

#endif /* RZ_X509_INTERNAL_H */

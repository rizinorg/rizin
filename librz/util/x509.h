// SPDX-FileCopyrightText: 2017-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_X509_INTERNAL_H
#define RZ_X509_INTERNAL_H

RZ_IPI bool rz_x509_algorithmidentifier_parse(RZ_NONNULL RzX509AlgorithmIdentifier *ai, RZ_NONNULL RzASN1Object *object);
RZ_IPI void rz_x509_algorithmidentifier_to_structure(RZ_NONNULL RzStructuredData *parent, RZ_NONNULL const RzX509AlgorithmIdentifier *ai);
RZ_IPI bool rz_x509_name_parse(RZ_NULLABLE RzX509Name *name, RZ_NULLABLE RzASN1Object *object);
RZ_IPI void rz_x509_algorithmidentifier_fini(RZ_NULLABLE RzX509AlgorithmIdentifier *ai);
RZ_IPI void rz_x509_name_fini(RZ_NULLABLE RzX509Name *name);
RZ_IPI void rz_x509_crl_free(RZ_NULLABLE RzX509CertificateRevocationList *crl);
RZ_IPI void rz_x509_name_to_structure(RZ_NULLABLE RzStructuredData *parent, RZ_NULLABLE RzX509Name *name);

#endif /* RZ_X509_INTERNAL_H */

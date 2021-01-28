#ifndef RZ_X509_INTERNAL_H
#define RZ_X509_INTERNAL_H

RZ_API bool rz_x509_parse_algorithmidentifier(RX509AlgorithmIdentifier *ai, RASN1Object *object);
RZ_API void rz_x509_free_algorithmidentifier(RX509AlgorithmIdentifier *ai);

RZ_API bool rz_x509_parse_subjectpublickeyinfo(RX509SubjectPublicKeyInfo *spki, RASN1Object *object);
RZ_API void rz_x509_free_subjectpublickeyinfo(RX509SubjectPublicKeyInfo *spki);

RZ_API bool rz_x509_parse_name(RX509Name *name, RASN1Object *object);
RZ_API void rz_x509_free_name(RX509Name *name);

RZ_API bool rz_x509_parse_extension(RX509Extension *ext, RASN1Object *object);
RZ_API void rz_x509_free_extension(RX509Extension *ex);

RZ_API bool rz_x509_parse_extensions(RX509Extensions *ext, RASN1Object *object);
RZ_API void rz_x509_free_extensions(RX509Extensions *ex);

RZ_API bool rz_x509_parse_tbscertificate(RX509TBSCertificate *tbsc, RASN1Object *object);
RZ_API void rz_x509_free_tbscertificate(RX509TBSCertificate *tbsc);

RZ_API RX509CRLEntry *rz_x509_parse_crlentry(RASN1Object *object);
RZ_API void rz_x509_name_dump(RX509Name *name, const char *pad, RzStrBuf *sb);

#endif /* RZ_X509_INTERNAL_H */

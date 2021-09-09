//
// Created by oleg on 08.08.2021.
//
#include "rz_basefind.h"
#include "rz_io.h"
//RZ_API ut64 rz_io_size(RzIO *io);
//ut64 sz = rz_io_size(core->io);
struct RzBasefinds {
	uint32_t offset;
	unsigned score;
};
bool filter[1 << CHAR_BIT];
static const size_t minLength = 10;
bool scan_char(uint8_t ch) {
	return filter[ch];
}
bool rz_vector_find(RzVector *vec, size_t value) {
	if (rz_vector_empty(vec)) {
		return false;
	}
	size_t *it;
	rz_vector_foreach(vec, it) {
		if (*it == value) {
			return true;
		}
	}
	return false;
}
RzVector *get_strings(RzVector *buf) {
	RzVector *results = rz_vector_new(sizeof(uint8_t), NULL, NULL);
	const size_t lenBuf = rz_vector_len(buf);
	printf("%s\n", "get_strings");
	if (lenBuf < minLength) {
		printf("%s\n", "ret res");
		return results;
	}
	for (size_t i = 1; i < lenBuf - minLength; ++i) {
		const uint8_t *ptr = &buf[i];
		size_t *ptr_i = &i;
		if (!scan_char(*(ptr - 1)) && rz_vector_find(results, i)) {
			//printf("%s\n", "rz vec push");
			rz_vector_push(results, ptr_i);
			printf("%d\n", i);
		}
	}
	return results;
}

//rz_vector_foreachu(vec, it)
//	if (!rz_vector_empty(vec)) {
//for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))

char *rz_bin_basefind(const char *infile) {
	//rz_io_open()
	FILE *ptrFile = fopen(infile, "rb");
	RzVector *fbuf = rz_vector_new(sizeof(uint8_t), NULL, NULL);
	if (ptrFile == NULL) {
		fputs("Ошибка файла", stderr);
		exit(1);
	}
	// определяем размер файла
	fseek(ptrFile, 0, SEEK_END);
	long lSize = ftell(ptrFile); // получаем размер в байтах
	rewind(ptrFile);
	rz_vector_reserve(fbuf, lSize);
	size_t result = fread(fbuf, 1, lSize, ptrFile);
	if (result != lSize) {
		fputs("Ошибка чтения", stderr);
		exit(3);
	}
	// я хочу считать файл в вектор

	//как я могу считать файл  RzVector
	printf("len fbuf: %zu\n", rz_vector_len(fbuf));
	RzVector *str_table = rz_vector_new(sizeof(uint8_t), NULL, NULL);
	printf("Total strings found: %zu\n", rz_vector_len(str_table));
	get_strings(fbuf);
	printf("Total strings found: %zu\n", rz_vector_len(str_table));
	RzVector *ptr_table = rz_vector_new(sizeof(struct RzBasefinds), NULL, NULL);
	fclose(ptrFile);

	//free(buffer);
	return "finisgh";
}

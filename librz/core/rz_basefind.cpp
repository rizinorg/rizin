#include "rz_basefind.h"
//
//#include <algorithm>
//#include <climits>
//#include <cstdint>
//#include <cstring>
//#include <fstream>
//#include <map>
//#include <unordered_set>
//#include <vector>
#include <iostream>
//static const size_t minLength = 10;
//static const size_t WORD_LEN = 4; //32-bit assumed in a few places below
//typedef uint32_t offset_t;
//typedef std::vector<std::pair<offset_t, unsigned>> ptable; //pointer table
//typedef std::unordered_set<offset_t> stable; //string table
//typedef std::vector<std::pair<offset_t, unsigned>> scorecard;
//
//class stringScanner {
//      private:
//	void set(unsigned char idx);
//	void setRange(unsigned char start, unsigned char end);
//
//      public:
//	stringScanner();
//	bool scan(const uint8_t *ptr);
//	bool scanChar(uint8_t ch);
//};
//stable get_strings(const std::vector<uint8_t> &buf);
//void high_scores(const scorecard &scores);
//ptable get_pointers(const std::vector<uint8_t> buf);
//
//void high_scores(const scorecard &scores) {
//#define MAX 20
//	unsigned i = 0;
//	printf("\nTop %i base address candidates:\n", MAX);
//	for (scorecard::const_reverse_iterator it = scores.rbegin(); i < MAX && it != scores.rend(); ++it, ++i) {
//		printf("0x%x\t%d\n", it->second, it->first);
//	}
//}
//
//ptable get_pointers(const std::vector<uint8_t> buf) {
//	const uint8_t *ptr = &buf[0];
//	const uint8_t *endptr = ptr + buf.size();
//	std::map<offset_t, unsigned> temp_table;
//	for (; ptr < endptr; ptr += WORD_LEN) {
//		offset_t offset;
//		//implicit assumption that host endian and target endian match
//		memcpy(&offset, ptr, WORD_LEN);
//		std::map<offset_t, unsigned>::iterator it = temp_table.find(offset);
//		if (it == temp_table.end()) {
//			temp_table[offset] = 1;
//		} else {
//			temp_table[offset]++;
//		}
//	}
//
//	ptable table;
//	for (std::map<offset_t, unsigned>::iterator iter = temp_table.begin(); iter != temp_table.end(); ++iter) {
//		table.push_back(std::make_pair(iter->first, iter->second));
//	}
//	return table;
//}
//
//bool filter[1 << CHAR_BIT];
//void stringScanner::set(unsigned char idx) {
//	filter[idx] = true;
//}
//void stringScanner::setRange(unsigned char start, unsigned char end) {
//	for (unsigned char i = start; i <= end; ++i)
//		set(i);
//}
//
//stringScanner::stringScanner() {
//	memset(filter, 0x00, sizeof(filter));
//	setRange('A', 'Z');
//	setRange('a', 'z');
//	setRange('0', '9');
//	static const char onesies[] = "/\\-:.,_$%'\"()[]<> ";
//	for (size_t i = 0; i < strlen(onesies); ++i)
//		set(onesies[i]);
//}
//
//bool stringScanner::scan(const uint8_t *ptr) {
//	for (const uint8_t *endptr = ptr + minLength; ptr < endptr; ++ptr) {
//		if (!filter[*ptr])
//			return false;
//	}
//	return true;
//}
//bool stringScanner::scanChar(uint8_t ch) {
//	return filter[ch];
//}
//
//stable get_strings(const std::vector<uint8_t> &buf) {
//	stable results;
//	stringScanner scanner;
//	if (buf.size() < minLength)
//		return results;
//
//	for (size_t i = 1; i < (buf.size() - minLength); ++i) {
//		const uint8_t *ptr = &buf[i];
//		if (!scanner.scanChar(*(ptr - 1))) {
//			if (scanner.scan(ptr)) {
//				results.insert(i);
//			}
//		}
//	}
//	return results;
//}
char *rz_bin_basefind() {
	return "im basefind";
}
//int irz_bin_basefind(const char *const args[]) {
//
//	const char *infile = args[1];
//
//	std::vector<uint8_t> fbuf;
//
//	{
//		std::ifstream f(infile, std::ios::binary | std::ios::ate);
//		if (!f.is_open()) {
//			printf("Unable to open %s\n", infile);
//			return 2;
//		}
//		fbuf.resize(f.tellg());
//		f.seekg(0);
//		f.read((char *)&fbuf[0], fbuf.size());
//		if (f.gcount() != fbuf.size()) {
//			printf("Unable to fully read %s\n", infile);
//			return 3;
//		}
//	}
//
//	printf("Scanning binary for strings...\n");
//	stable str_table = get_strings(fbuf);
//	printf("Total strings found: %d\n", str_table.size());
//
//	printf("Scanning binary for pointers...\n");
//	ptable ptr_table = get_pointers(fbuf);
//	printf("Total pointers found: %d\n", ptr_table.size());
//
//	//    signal.signal(signal.SIGINT, high_scores)
//
//	unsigned top_score = 0;
//	scorecard scores;
//
//	for (offset_t base = 0; base < 0xf0000000UL; base += 0x1000) {
//		unsigned score = 0;
//		for (ptable::iterator iter = ptr_table.begin(); iter != ptr_table.end(); ++iter) {
//			offset_t ptr = iter->first;
//			if (ptr < base)
//				continue;
//			if (ptr >= (base + fbuf.size()))
//				continue;
//			unsigned offset = ptr - base;
//			if (str_table.find(offset) != str_table.end())
//				score += iter->second;
//		}
//		if (score) {
//			scores.push_back(std::make_pair(score, base));
//			if (score > top_score) {
//				top_score = score;
//				printf("New highest score, 0x%x: %d\n", base, score);
//			}
//		}
//	}
//	std::sort(scores.begin(), scores.end());
//	high_scores(scores);
//}
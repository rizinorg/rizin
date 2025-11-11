// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include "rz_util/rz_assert.h"
#include "rz_util/rz_str.h"
#include "rz_util/rz_unicode.h"

/**
 * \brief Unicode control ranges.
 *
 * Table generated with `ucd-generate general-category`.
 * See: https://github.com/BurntSushi/ucd-generate
 *
 * Unicode version: 16.0.0.
 */
const RzUnicodeRangeTable surrogate_ranges = {
	{ 55296, 57343 },
};

/**
 * \brief Unicode control ranges.
 *
 * Table generated with `ucd-generate general-category`.
 * See: https://github.com/BurntSushi/ucd-generate
 *
 * Unicode version: 16.0.0.
 */
const RzUnicodeRangeTable control_ranges = {
	{ 0, 31 },
	{ 127, 159 },
};

/**
 * \brief Unicode private use ranges.
 *
 * Table generated with `ucd-generate general-category`.
 * See: https://github.com/BurntSushi/ucd-generate
 *
 * Unicode version: 16.0.0.
 */
const RzUnicodeRangeTable private_ranges = {
	{ 57344, 63743 },
	{ 983040, 1048573 },
	{ 1048576, 1114109 },
};

/**
 * \brief Unicode format ranges.
 *
 * Table generated with `ucd-generate general-category`.
 * See: https://github.com/BurntSushi/ucd-generate
 *
 * Unicode version: 16.0.0.
 */
const RzUnicodeRangeTable format_ranges = {
	{ 173, 173 },
	{ 1536, 1541 },
	{ 1564, 1564 },
	{ 1757, 1757 },
	{ 1807, 1807 },
	{ 2192, 2193 },
	{ 2274, 2274 },
	{ 6158, 6158 },
	{ 8203, 8207 },
	{ 8234, 8238 },
	{ 8288, 8292 },
	{ 8294, 8303 },
	{ 65279, 65279 },
	{ 65529, 65531 },
	{ 69821, 69821 },
	{ 69837, 69837 },
	{ 78896, 78911 },
	{ 113824, 113827 },
	{ 119155, 119162 },
	{ 917505, 917505 },
	{ 917536, 917631 },

};

/**
 * \brief Unicode undefined ranges.
 *
 * Table generated with `ucd-generate general-category`.
 * See: https://github.com/BurntSushi/ucd-generate
 *
 * Unicode version: 16.0.0.
 */
const RzUnicodeRangeTable undefined_ranges = {
	{ 888, 889 }, { 896, 899 }, { 907, 907 }, { 909, 909 }, { 930, 930 }, { 1328, 1328 },
	{ 1367, 1368 }, { 1419, 1420 }, { 1424, 1424 }, { 1480, 1487 }, { 1515, 1518 },
	{ 1525, 1535 }, { 1806, 1806 }, { 1867, 1868 }, { 1970, 1983 }, { 2043, 2044 },
	{ 2094, 2095 }, { 2111, 2111 }, { 2140, 2141 }, { 2143, 2143 }, { 2155, 2159 },
	{ 2191, 2191 }, { 2194, 2198 }, { 2436, 2436 }, { 2445, 2446 }, { 2449, 2450 },
	{ 2473, 2473 }, { 2481, 2481 }, { 2483, 2485 }, { 2490, 2491 }, { 2501, 2502 },
	{ 2505, 2506 }, { 2511, 2518 }, { 2520, 2523 }, { 2526, 2526 }, { 2532, 2533 },
	{ 2559, 2560 }, { 2564, 2564 }, { 2571, 2574 }, { 2577, 2578 }, { 2601, 2601 },
	{ 2609, 2609 }, { 2612, 2612 }, { 2615, 2615 }, { 2618, 2619 }, { 2621, 2621 },
	{ 2627, 2630 }, { 2633, 2634 }, { 2638, 2640 }, { 2642, 2648 }, { 2653, 2653 },
	{ 2655, 2661 }, { 2679, 2688 }, { 2692, 2692 }, { 2702, 2702 }, { 2706, 2706 },
	{ 2729, 2729 }, { 2737, 2737 }, { 2740, 2740 }, { 2746, 2747 }, { 2758, 2758 },
	{ 2762, 2762 }, { 2766, 2767 }, { 2769, 2783 }, { 2788, 2789 }, { 2802, 2808 },
	{ 2816, 2816 }, { 2820, 2820 }, { 2829, 2830 }, { 2833, 2834 }, { 2857, 2857 },
	{ 2865, 2865 }, { 2868, 2868 }, { 2874, 2875 }, { 2885, 2886 }, { 2889, 2890 },
	{ 2894, 2900 }, { 2904, 2907 }, { 2910, 2910 }, { 2916, 2917 }, { 2936, 2945 },
	{ 2948, 2948 }, { 2955, 2957 }, { 2961, 2961 }, { 2966, 2968 }, { 2971, 2971 },
	{ 2973, 2973 }, { 2976, 2978 }, { 2981, 2983 }, { 2987, 2989 }, { 3002, 3005 },
	{ 3011, 3013 }, { 3017, 3017 }, { 3022, 3023 }, { 3025, 3030 }, { 3032, 3045 },
	{ 3067, 3071 }, { 3085, 3085 }, { 3089, 3089 }, { 3113, 3113 }, { 3130, 3131 },
	{ 3141, 3141 }, { 3145, 3145 }, { 3150, 3156 }, { 3159, 3159 }, { 3163, 3164 },
	{ 3166, 3167 }, { 3172, 3173 }, { 3184, 3190 }, { 3213, 3213 }, { 3217, 3217 },
	{ 3241, 3241 }, { 3252, 3252 }, { 3258, 3259 }, { 3269, 3269 }, { 3273, 3273 },
	{ 3278, 3284 }, { 3287, 3292 }, { 3295, 3295 }, { 3300, 3301 }, { 3312, 3312 },
	{ 3316, 3327 }, { 3341, 3341 }, { 3345, 3345 }, { 3397, 3397 }, { 3401, 3401 },
	{ 3408, 3411 }, { 3428, 3429 }, { 3456, 3456 }, { 3460, 3460 }, { 3479, 3481 },
	{ 3506, 3506 }, { 3516, 3516 }, { 3518, 3519 }, { 3527, 3529 }, { 3531, 3534 },
	{ 3541, 3541 }, { 3543, 3543 }, { 3552, 3557 }, { 3568, 3569 }, { 3573, 3584 },
	{ 3643, 3646 }, { 3676, 3712 }, { 3715, 3715 }, { 3717, 3717 }, { 3723, 3723 },
	{ 3748, 3748 }, { 3750, 3750 }, { 3774, 3775 }, { 3781, 3781 }, { 3783, 3783 },
	{ 3791, 3791 }, { 3802, 3803 }, { 3808, 3839 }, { 3912, 3912 }, { 3949, 3952 },
	{ 3992, 3992 }, { 4029, 4029 }, { 4045, 4045 }, { 4059, 4095 }, { 4294, 4294 },
	{ 4296, 4300 }, { 4302, 4303 }, { 4681, 4681 }, { 4686, 4687 }, { 4695, 4695 },
	{ 4697, 4697 }, { 4702, 4703 }, { 4745, 4745 }, { 4750, 4751 }, { 4785, 4785 },
	{ 4790, 4791 }, { 4799, 4799 }, { 4801, 4801 }, { 4806, 4807 }, { 4823, 4823 },
	{ 4881, 4881 }, { 4886, 4887 }, { 4955, 4956 }, { 4989, 4991 }, { 5018, 5023 },
	{ 5110, 5111 }, { 5118, 5119 }, { 5789, 5791 }, { 5881, 5887 }, { 5910, 5918 },
	{ 5943, 5951 }, { 5972, 5983 }, { 5997, 5997 }, { 6001, 6001 }, { 6004, 6015 },
	{ 6110, 6111 }, { 6122, 6127 }, { 6138, 6143 }, { 6170, 6175 }, { 6265, 6271 },
	{ 6315, 6319 }, { 6390, 6399 }, { 6431, 6431 }, { 6444, 6447 }, { 6460, 6463 },
	{ 6465, 6467 }, { 6510, 6511 }, { 6517, 6527 }, { 6572, 6575 }, { 6602, 6607 },
	{ 6619, 6621 }, { 6684, 6685 }, { 6751, 6751 }, { 6781, 6782 }, { 6794, 6799 },
	{ 6810, 6815 }, { 6830, 6831 }, { 6863, 6911 }, { 6989, 6989 }, { 7156, 7163 },
	{ 7224, 7226 }, { 7242, 7244 }, { 7307, 7311 }, { 7355, 7356 }, { 7368, 7375 },
	{ 7419, 7423 }, { 7958, 7959 }, { 7966, 7967 }, { 8006, 8007 }, { 8014, 8015 },
	{ 8024, 8024 }, { 8026, 8026 }, { 8028, 8028 }, { 8030, 8030 }, { 8062, 8063 },
	{ 8117, 8117 }, { 8133, 8133 }, { 8148, 8149 }, { 8156, 8156 }, { 8176, 8177 },
	{ 8181, 8181 }, { 8191, 8191 }, { 8293, 8293 }, { 8306, 8307 }, { 8335, 8335 },
	{ 8349, 8351 }, { 8385, 8399 }, { 8433, 8447 }, { 8588, 8591 }, { 9258, 9279 },
	{ 9291, 9311 }, { 11124, 11125 }, { 11158, 11158 }, { 11508, 11512 },
	{ 11558, 11558 }, { 11560, 11564 }, { 11566, 11567 }, { 11624, 11630 },
	{ 11633, 11646 }, { 11671, 11679 }, { 11687, 11687 }, { 11695, 11695 },
	{ 11703, 11703 }, { 11711, 11711 }, { 11719, 11719 }, { 11727, 11727 },
	{ 11735, 11735 }, { 11743, 11743 }, { 11870, 11903 }, { 11930, 11930 },
	{ 12020, 12031 }, { 12246, 12271 }, { 12352, 12352 }, { 12439, 12440 },
	{ 12544, 12548 }, { 12592, 12592 }, { 12687, 12687 }, { 12774, 12782 },
	{ 12831, 12831 }, { 42125, 42127 }, { 42183, 42191 }, { 42540, 42559 },
	{ 42744, 42751 }, { 42958, 42959 }, { 42962, 42962 }, { 42964, 42964 },
	{ 42973, 42993 }, { 43053, 43055 }, { 43066, 43071 }, { 43128, 43135 },
	{ 43206, 43213 }, { 43226, 43231 }, { 43348, 43358 }, { 43389, 43391 },
	{ 43470, 43470 }, { 43482, 43485 }, { 43519, 43519 }, { 43575, 43583 },
	{ 43598, 43599 }, { 43610, 43611 }, { 43715, 43738 }, { 43767, 43776 },
	{ 43783, 43784 }, { 43791, 43792 }, { 43799, 43807 }, { 43815, 43815 },
	{ 43823, 43823 }, { 43884, 43887 }, { 44014, 44015 }, { 44026, 44031 },
	{ 55204, 55215 }, { 55239, 55242 }, { 55292, 55295 }, { 64110, 64111 },
	{ 64218, 64255 }, { 64263, 64274 }, { 64280, 64284 }, { 64311, 64311 },
	{ 64317, 64317 }, { 64319, 64319 }, { 64322, 64322 }, { 64325, 64325 },
	{ 64451, 64466 }, { 64912, 64913 }, { 64968, 64974 }, { 64976, 65007 },
	{ 65050, 65055 }, { 65107, 65107 }, { 65127, 65127 }, { 65132, 65135 },
	{ 65141, 65141 }, { 65277, 65278 }, { 65280, 65280 }, { 65471, 65473 },
	{ 65480, 65481 }, { 65488, 65489 }, { 65496, 65497 }, { 65501, 65503 },
	{ 65511, 65511 }, { 65519, 65528 }, { 65534, 65535 }, { 65548, 65548 },
	{ 65575, 65575 }, { 65595, 65595 }, { 65598, 65598 }, { 65614, 65615 },
	{ 65630, 65663 }, { 65787, 65791 }, { 65795, 65798 }, { 65844, 65846 },
	{ 65935, 65935 }, { 65949, 65951 }, { 65953, 65999 }, { 66046, 66175 },
	{ 66205, 66207 }, { 66257, 66271 }, { 66300, 66303 }, { 66340, 66348 },
	{ 66379, 66383 }, { 66427, 66431 }, { 66462, 66462 }, { 66500, 66503 },
	{ 66518, 66559 }, { 66718, 66719 }, { 66730, 66735 }, { 66772, 66775 },
	{ 66812, 66815 }, { 66856, 66863 }, { 66916, 66926 }, { 66939, 66939 },
	{ 66955, 66955 }, { 66963, 66963 }, { 66966, 66966 }, { 66978, 66978 },
	{ 66994, 66994 }, { 67002, 67002 }, { 67005, 67007 }, { 67060, 67071 },
	{ 67383, 67391 }, { 67414, 67423 }, { 67432, 67455 }, { 67462, 67462 },
	{ 67505, 67505 }, { 67515, 67583 }, { 67590, 67591 }, { 67593, 67593 },
	{ 67638, 67638 }, { 67641, 67643 }, { 67645, 67646 }, { 67670, 67670 },
	{ 67743, 67750 }, { 67760, 67807 }, { 67827, 67827 }, { 67830, 67834 },
	{ 67868, 67870 }, { 67898, 67902 }, { 67904, 67967 }, { 68024, 68027 },
	{ 68048, 68049 }, { 68100, 68100 }, { 68103, 68107 }, { 68116, 68116 },
	{ 68120, 68120 }, { 68150, 68151 }, { 68155, 68158 }, { 68169, 68175 },
	{ 68185, 68191 }, { 68256, 68287 }, { 68327, 68330 }, { 68343, 68351 },
	{ 68406, 68408 }, { 68438, 68439 }, { 68467, 68471 }, { 68498, 68504 },
	{ 68509, 68520 }, { 68528, 68607 }, { 68681, 68735 }, { 68787, 68799 },
	{ 68851, 68857 }, { 68904, 68911 }, { 68922, 68927 }, { 68966, 68968 },
	{ 68998, 69005 }, { 69008, 69215 }, { 69247, 69247 }, { 69290, 69290 },
	{ 69294, 69295 }, { 69298, 69313 }, { 69317, 69371 }, { 69416, 69423 },
	{ 69466, 69487 }, { 69514, 69551 }, { 69580, 69599 }, { 69623, 69631 },
	{ 69710, 69713 }, { 69750, 69758 }, { 69827, 69836 }, { 69838, 69839 },
	{ 69865, 69871 }, { 69882, 69887 }, { 69941, 69941 }, { 69960, 69967 },
	{ 70007, 70015 }, { 70112, 70112 }, { 70133, 70143 }, { 70162, 70162 },
	{ 70210, 70271 }, { 70279, 70279 }, { 70281, 70281 }, { 70286, 70286 },
	{ 70302, 70302 }, { 70314, 70319 }, { 70379, 70383 }, { 70394, 70399 },
	{ 70404, 70404 }, { 70413, 70414 }, { 70417, 70418 }, { 70441, 70441 },
	{ 70449, 70449 }, { 70452, 70452 }, { 70458, 70458 }, { 70469, 70470 },
	{ 70473, 70474 }, { 70478, 70479 }, { 70481, 70486 }, { 70488, 70492 },
	{ 70500, 70501 }, { 70509, 70511 }, { 70517, 70527 }, { 70538, 70538 },
	{ 70540, 70541 }, { 70543, 70543 }, { 70582, 70582 }, { 70593, 70593 },
	{ 70595, 70596 }, { 70598, 70598 }, { 70603, 70603 }, { 70614, 70614 },
	{ 70617, 70624 }, { 70627, 70655 }, { 70748, 70748 }, { 70754, 70783 },
	{ 70856, 70863 }, { 70874, 71039 }, { 71094, 71095 }, { 71134, 71167 },
	{ 71237, 71247 }, { 71258, 71263 }, { 71277, 71295 }, { 71354, 71359 },
	{ 71370, 71375 }, { 71396, 71423 }, { 71451, 71452 }, { 71468, 71471 },
	{ 71495, 71679 }, { 71740, 71839 }, { 71923, 71934 }, { 71943, 71944 },
	{ 71946, 71947 }, { 71956, 71956 }, { 71959, 71959 }, { 71990, 71990 },
	{ 71993, 71994 }, { 72007, 72015 }, { 72026, 72095 }, { 72104, 72105 },
	{ 72152, 72153 }, { 72165, 72191 }, { 72264, 72271 }, { 72355, 72367 },
	{ 72441, 72447 }, { 72458, 72639 }, { 72674, 72687 }, { 72698, 72703 },
	{ 72713, 72713 }, { 72759, 72759 }, { 72774, 72783 }, { 72813, 72815 },
	{ 72848, 72849 }, { 72872, 72872 }, { 72887, 72959 }, { 72967, 72967 },
	{ 72970, 72970 }, { 73015, 73017 }, { 73019, 73019 }, { 73022, 73022 },
	{ 73032, 73039 }, { 73050, 73055 }, { 73062, 73062 }, { 73065, 73065 },
	{ 73103, 73103 }, { 73106, 73106 }, { 73113, 73119 }, { 73130, 73439 },
	{ 73465, 73471 }, { 73489, 73489 }, { 73531, 73533 }, { 73563, 73647 },
	{ 73649, 73663 }, { 73714, 73726 }, { 74650, 74751 }, { 74863, 74863 },
	{ 74869, 74879 }, { 75076, 77711 }, { 77811, 77823 }, { 78934, 78943 },
	{ 82939, 82943 }, { 83527, 90367 }, { 90426, 92159 }, { 92729, 92735 },
	{ 92767, 92767 }, { 92778, 92781 }, { 92863, 92863 }, { 92874, 92879 },
	{ 92910, 92911 }, { 92918, 92927 }, { 92998, 93007 }, { 93018, 93018 },
	{ 93026, 93026 }, { 93048, 93052 }, { 93072, 93503 }, { 93562, 93759 },
	{ 93851, 93951 }, { 94027, 94030 }, { 94088, 94094 }, { 94112, 94175 },
	{ 94181, 94191 }, { 94194, 94207 }, { 100344, 100351 }, { 101590, 101630 },
	{ 101641, 110575 }, { 110580, 110580 }, { 110588, 110588 }, { 110591, 110591 },
	{ 110883, 110897 }, { 110899, 110927 }, { 110931, 110932 }, { 110934, 110947 },
	{ 110952, 110959 }, { 111356, 113663 }, { 113771, 113775 }, { 113789, 113791 },
	{ 113801, 113807 }, { 113818, 113819 }, { 113828, 117759 }, { 118010, 118015 },
	{ 118452, 118527 }, { 118574, 118575 }, { 118599, 118607 }, { 118724, 118783 },
	{ 119030, 119039 }, { 119079, 119080 }, { 119275, 119295 }, { 119366, 119487 },
	{ 119508, 119519 }, { 119540, 119551 }, { 119639, 119647 }, { 119673, 119807 },
	{ 119893, 119893 }, { 119965, 119965 }, { 119968, 119969 }, { 119971, 119972 },
	{ 119975, 119976 }, { 119981, 119981 }, { 119994, 119994 }, { 119996, 119996 },
	{ 120004, 120004 }, { 120070, 120070 }, { 120075, 120076 }, { 120085, 120085 },
	{ 120093, 120093 }, { 120122, 120122 }, { 120127, 120127 }, { 120133, 120133 },
	{ 120135, 120137 }, { 120145, 120145 }, { 120486, 120487 }, { 120780, 120781 },
	{ 121484, 121498 }, { 121504, 121504 }, { 121520, 122623 }, { 122655, 122660 },
	{ 122667, 122879 }, { 122887, 122887 }, { 122905, 122906 }, { 122914, 122914 },
	{ 122917, 122917 }, { 122923, 122927 }, { 122990, 123022 }, { 123024, 123135 },
	{ 123181, 123183 }, { 123198, 123199 }, { 123210, 123213 }, { 123216, 123535 },
	{ 123567, 123583 }, { 123642, 123646 }, { 123648, 124111 }, { 124154, 124367 },
	{ 124411, 124414 }, { 124416, 124895 }, { 124903, 124903 }, { 124908, 124908 },
	{ 124911, 124911 }, { 124927, 124927 }, { 125125, 125126 }, { 125143, 125183 },
	{ 125260, 125263 }, { 125274, 125277 }, { 125280, 126064 }, { 126133, 126208 },
	{ 126270, 126463 }, { 126468, 126468 }, { 126496, 126496 }, { 126499, 126499 },
	{ 126501, 126502 }, { 126504, 126504 }, { 126515, 126515 }, { 126520, 126520 },
	{ 126522, 126522 }, { 126524, 126529 }, { 126531, 126534 }, { 126536, 126536 },
	{ 126538, 126538 }, { 126540, 126540 }, { 126544, 126544 }, { 126547, 126547 },
	{ 126549, 126550 }, { 126552, 126552 }, { 126554, 126554 }, { 126556, 126556 },
	{ 126558, 126558 }, { 126560, 126560 }, { 126563, 126563 }, { 126565, 126566 },
	{ 126571, 126571 }, { 126579, 126579 }, { 126584, 126584 }, { 126589, 126589 },
	{ 126591, 126591 }, { 126602, 126602 }, { 126620, 126624 }, { 126628, 126628 },
	{ 126634, 126634 }, { 126652, 126703 }, { 126706, 126975 }, { 127020, 127023 },
	{ 127124, 127135 }, { 127151, 127152 }, { 127168, 127168 }, { 127184, 127184 },
	{ 127222, 127231 }, { 127406, 127461 }, { 127491, 127503 }, { 127548, 127551 },
	{ 127561, 127567 }, { 127570, 127583 }, { 127590, 127743 }, { 128728, 128731 },
	{ 128749, 128751 }, { 128765, 128767 }, { 128887, 128890 }, { 128986, 128991 },
	{ 129004, 129007 }, { 129009, 129023 }, { 129036, 129039 }, { 129096, 129103 },
	{ 129114, 129119 }, { 129160, 129167 }, { 129198, 129199 }, { 129212, 129215 },
	{ 129218, 129279 }, { 129620, 129631 }, { 129646, 129647 }, { 129661, 129663 },
	{ 129674, 129678 }, { 129735, 129741 }, { 129757, 129758 }, { 129770, 129775 },
	{ 129785, 129791 }, { 129939, 129939 }, { 130042, 131071 }, { 173792, 173823 },
	{ 177978, 177983 }, { 178206, 178207 }, { 183970, 183983 }, { 191457, 191471 },
	{ 192094, 194559 }, { 195102, 196607 }, { 201547, 201551 }, { 205744, 917504 },
	{ 917506, 917535 }, { 917632, 917759 }, { 918000, 983039 }, { 1048574, 1048575 },
	{ 1114110, 1114111 }, { 0x110000, 0xFFFFFFFF }
};

static bool bin_search_range(RzCodePoint cp, const RzUnicodeRangeTable table, size_t table_size) {
	size_t low = 0;
	size_t hi = table_size - 1;

	do {
		size_t mid = (low + hi) >> 1;
		if (cp >= table[mid].from && cp <= table[mid].to) {
			return true;
		}
		if (low == hi) {
			break;
		}
		if (mid < table_size && cp > table[mid].to) {
			low = mid + 1;
		}
		if (mid < table_size && cp < table[mid].from) {
			hi = mid - 1;
		}
	} while (low <= hi);

	return false;
}

/**
 * \brief Returns true when the RzCodePoint is a defined Unicode code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is defined, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_defined(const RzCodePoint c) {
	if (c > RZ_UNICODE_LAST_CODE_POINT) {
		return false;
	}
	return !bin_search_range(c, undefined_ranges, RZ_ARRAY_SIZE(undefined_ranges));
}

/**
 * \brief Returns true when the RzCodePoint is a defined Unicode code point and not a surrogate.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is defined and not a surrogate, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_legal_decode(const RzCodePoint c) {
	return rz_unicode_code_point_is_defined(c) && !rz_unicode_code_point_is_surrogate(c);
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode control code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a control code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_control(const RzCodePoint c) {
	return (c >= control_ranges[0].from && c <= control_ranges[0].to) ||
		(c >= control_ranges[1].from && c <= control_ranges[1].to);
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode surrogate code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a surrogate code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_surrogate(const RzCodePoint c) {
	return c >= surrogate_ranges[0].from && c <= surrogate_ranges[0].to;
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode private code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a private code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_private(const RzCodePoint c) {
	return bin_search_range(c, private_ranges, RZ_ARRAY_SIZE(private_ranges));
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode format code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a format code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_format(const RzCodePoint c) {
	return bin_search_range(c, format_ranges, RZ_ARRAY_SIZE(format_ranges));
}

/**
 * \brief Returns true when the RzCodePoint is a printable symbol.
 * Printable means:
 * - Is defined Unicode code point.
 * - Outside of the control plain.
 * - Not a surrogate.
 * - Not from the private range.
 * - Not a format character.
 *
 * NOTE: This means \n, \t, \r etc. are considered not printable!
 * NOTE: Be careful when passing char values to it. On some platforms
 * they might get sign extended and the result is an invalid code point.
 *
 * \param  c RzCodePoint value to test.
 *
 * \return   true if the code point is printable, otherwise false.
 */
RZ_API bool rz_unicode_code_point_is_printable(const RzCodePoint c) {
	// RzCodePoints are most commonly single bytes.
	// We can early out with this common case.
	if (c <= RZ_UNICODE_LAST_ASCII) {
		// Check for control plain of ASCII here, because they are so common.
		return IS_PRINTABLE(c);
	}
	return !rz_unicode_code_point_is_control(c) &&
		rz_unicode_code_point_is_defined(c) &&
		!rz_unicode_code_point_is_surrogate(c) &&
		!rz_unicode_code_point_is_format(c) &&
		!rz_unicode_code_point_is_private(c);
}

RZ_API RzStrEnc rz_unicode_bom_encoding(const ut8 *ptr, size_t ptrlen) {
	rz_return_val_if_fail(ptr, RZ_STRING_ENC_GUESS);
	if (ptrlen > 3) {
		if (ptr[0] == 0xff && ptr[1] == 0xfe && !ptr[2] && !ptr[3]) {
			return RZ_STRING_ENC_UTF32LE;
		}
		if (!ptr[0] && !ptr[1] && ptr[2] == 0xfe && ptr[3] == 0xff) {
			return RZ_STRING_ENC_UTF32BE;
		}
	}
	if (ptrlen > 2) {
		if (ptr[0] == 0xef && ptr[1] == 0xbb && ptr[2] == 0xbf) {
			return RZ_STRING_ENC_UTF8;
		}
	}
	if (ptrlen > 1) {
		if (ptr[0] == 0xff && ptr[1] == 0xfe) {
			return RZ_STRING_ENC_UTF16LE;
		}
		if (ptr[0] == 0xfe && ptr[1] == 0xff) {
			return RZ_STRING_ENC_UTF16BE;
		}
	}
	return RZ_STRING_ENC_GUESS;
}

static bool short_escape(RzCodePoint code_point, char **dst, const RzStrEscOptions *opt) {
	char *q = *dst;
	switch (code_point) {
	case '\n':
		*q++ = '\\';
		*q++ = opt->dot_nl ? 'l' : 'n';
		break;
	case '\r':
		*q++ = '\\';
		*q++ = 'r';
		break;
	case '\\':
		if (opt->esc_bslash) {
			*q++ = '\\';
		}
		*q++ = '\\';
		break;
	case '\t':
		*q++ = '\\';
		*q++ = 't';
		break;
	case '"':
		if (opt->esc_double_quotes) {
			*q++ = '\\';
		}
		*q++ = '"';
		break;
	case '\f':
		*q++ = '\\';
		*q++ = 'f';
		break;
	case '\b':
		*q++ = '\\';
		*q++ = 'b';
		break;
	case '\v':
		*q++ = '\\';
		*q++ = 'v';
		break;
	case '\a':
		*q++ = '\\';
		*q++ = 'a';
		break;
	case '\x1b':
		*q++ = '\\';
		*q++ = 'e';
		break;
	default:
		return false;
	}
	*dst = q;
	return true;
}

/**
 * \brief Converts an unicode characters to the \U00hhhhhh backslash representation.
 * Common control characters like (new line, tab etc.) are escaped
 * to their short form ('\n', '\r', '\t' etc.).
 *
 * NOTE: The \p dst pointer is incremented up to 10 bytes (if \U00hhhhhh is copied into it).
 * NOTE: This function _ignores_ opt->keep_printable.
 *
 * \param code_point The code point to escape.
 * \param dst String pointer to write the escaped code point into.
 * It must have at least a length of 11 (10 + '\0'). It gets incremented by the amount of bytes copied into it.
 * \param opt The encoding options structure.
 **/
RZ_API void rz_unicode_code_point_escape(RzCodePoint code_point, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt) {
	rz_return_if_fail(dst && opt);

	char *q = *dst;
	if (opt->show_asciidot && !IS_PRINTABLE(code_point)) {
		*q++ = '.';
		goto assign_return;
	} else if (short_escape(code_point, &q, opt)) {
		goto assign_return;
	} else {
		rz_snprintf(q, RZ_UNICODE_ESCAPED_STR_WIDTH + 1, "\\U00%06" PFMT32x, code_point);
		q += RZ_UNICODE_ESCAPED_STR_WIDTH;
	}
assign_return:
	*dst = q;
}

/**
 * \brief Escapes an unprintable character to C-like backslash representation '\xhh'.
 * Common control characters like (new line, tab etc.) are escaped
 * to their short form ('\n', '\r', '\t' etc.).
 *
 * NOTE: The \p dst pointer is incremented by 2 to 4 bytes.
 * NOTE: This function _ignores_ opt->keep_printable.
 *
 * \param ch The character to escape.
 * \param dst pointer where pointer to the resulting characters sequence is put.
 * \param opt pointer to encoding options structure.
 **/
RZ_API void rz_unicode_byte_escape(char ch, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt) {
	rz_return_if_fail(dst && opt);
	char *q = *dst;
	if (opt->show_asciidot && !IS_PRINTABLE(ch)) {
		*q++ = '.';
		goto assign_return;
	} else if (short_escape(ch, &q, opt)) {
		goto assign_return;
	} else {
		*q++ = '\\';
		*q++ = 'x';
		*q++ = "0123456789abcdef"[ch >> 4 & 0xf];
		*q++ = "0123456789abcdef"[ch & 0xf];
	}
assign_return:
	*dst = q;
}

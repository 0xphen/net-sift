pub mod aggregator;
pub mod parsers;

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn run_test() {
//         let frames = [
//             60, 34, 251, 165, 184, 202, 180, 28, 48, 182, 93, 120, 8, 0, 69, 0, 5, 160, 22, 43, 64,
//             0, 95, 6, 159, 226, 118, 179, 40, 116, 192, 168, 0, 123, 118, 88, 226, 105, 230, 83,
//             76, 55, 63, 197, 136, 176, 128, 16, 16, 1, 142, 83, 0, 0, 1, 1, 8, 10, 2, 4, 83, 111,
//             145, 186, 142, 229, 206, 219, 128, 122, 192, 126, 244, 189, 126, 234, 229, 18, 100,
//             150, 104, 114, 187, 244, 222, 16, 160, 194, 133, 237, 181, 243, 122, 130, 2, 97, 210,
//             3, 117, 229, 88, 174, 176, 44, 30, 188, 160, 108, 230, 90, 222, 59, 235, 222, 149, 186,
//             129, 3, 239, 216, 88, 202, 22, 233, 110, 31, 149, 65, 61, 104, 255, 200, 211, 58, 114,
//             67, 150, 240, 124, 139, 164, 60, 3, 79, 23, 102, 111, 109, 41, 196, 176, 172, 95, 243,
//             99, 19, 112, 26, 91, 207, 0, 217, 116, 194, 136, 94, 142, 223, 101, 50, 228, 122, 52,
//             195, 8, 67, 8, 196, 236, 68, 49, 202, 185, 100, 204, 169, 52, 73, 9, 215, 36, 112, 24,
//             13, 238, 95, 156, 107, 121, 154, 219, 113, 109, 217, 19, 156, 162, 100, 252, 241, 107,
//             142, 140, 88, 122, 72, 178, 175, 236, 181, 108, 161, 112, 219, 85, 121, 254, 152, 233,
//             41, 25, 18, 146, 239, 243, 138, 10, 143, 49, 141, 83, 185, 78, 207, 76, 33, 73, 154,
//             45, 38, 40, 213, 79, 151, 238, 223, 228, 229, 44, 162, 31, 109, 211, 104, 86, 238, 246,
//             136, 6, 205, 230, 167, 209, 13, 141, 227, 10, 51, 126, 98, 107, 238, 80, 147, 239, 136,
//             79, 74, 239, 134, 204, 223, 38, 41, 21, 183, 228, 39, 58, 183, 209, 90, 138, 227, 71,
//             213, 40, 71, 135, 243, 61, 219, 1, 168, 238, 97, 210, 80, 177, 21, 157, 103, 241, 242,
//             133, 154, 111, 209, 150, 58, 27, 91, 246, 10, 235, 126, 92, 240, 83, 51, 10, 243, 56,
//             144, 212, 216, 58, 89, 36, 118, 26, 81, 45, 8, 69, 151, 246, 98, 249, 136, 224, 39, 17,
//             151, 229, 63, 229, 167, 180, 58, 238, 133, 220, 151, 216, 6, 18, 67, 106, 19, 208, 239,
//             147, 103, 15, 9, 43, 150, 138, 63, 114, 223, 39, 178, 167, 88, 108, 68, 137, 196, 7,
//             87, 67, 219, 6, 103, 89, 250, 47, 135, 80, 200, 8, 250, 86, 208, 92, 77, 23, 91, 54,
//             246, 184, 76, 97, 185, 224, 128, 94, 25, 210, 175, 183, 130, 106, 111, 177, 223, 57,
//             56, 83, 209, 66, 59, 242, 98, 138, 122, 116, 193, 193, 244, 188, 197, 10, 89, 249, 255,
//             96, 83, 134, 105, 100, 243, 102, 244, 186, 78, 101, 241, 22, 103, 222, 138, 249, 252,
//             25, 106, 170, 243, 193, 94, 209, 196, 225, 10, 55, 8, 222, 255, 126, 193, 64, 195, 250,
//             172, 222, 26, 4, 51, 133, 153, 157, 95, 74, 29, 237, 100, 11, 252, 198, 14, 144, 239,
//             178, 54, 64, 179, 148, 200, 52, 183, 155, 172, 55, 58, 106, 90, 42, 28, 134, 95, 15,
//             159, 69, 174, 0, 24, 21, 64, 41, 118, 22, 185, 172, 185, 201, 9, 149, 237, 195, 112,
//             215, 77, 178, 75, 215, 176, 122, 110, 96, 202, 184, 79, 199, 3, 130, 133, 16, 149, 147,
//             119, 24, 81, 244, 124, 107, 102, 208, 159, 138, 186, 182, 104, 213, 116, 65, 130, 209,
//             199, 234, 106, 15, 23, 203, 245, 220, 194, 228, 197, 110, 40, 82, 249, 10, 81, 199, 78,
//             73, 100, 52, 109, 144, 150, 100, 254, 55, 160, 143, 124, 223, 155, 215, 62, 175, 166,
//             226, 226, 140, 122, 126, 74, 222, 190, 66, 211, 179, 46, 116, 140, 72, 243, 66, 102,
//             141, 169, 188, 168, 78, 193, 101, 138, 156, 111, 162, 89, 229, 3, 102, 249, 1, 105, 60,
//             7, 2, 35, 78, 121, 121, 33, 4, 222, 221, 45, 238, 125, 211, 118, 8, 15, 226, 1, 180,
//             134, 42, 87, 243, 130, 175, 150, 85, 130, 6, 227, 226, 202, 140, 123, 121, 9, 253, 178,
//             31, 224, 18, 78, 87, 245, 97, 116, 10, 93, 74, 51, 125, 210, 57, 183, 150, 236, 47, 52,
//             201, 222, 252, 38, 36, 185, 66, 56, 49, 13, 5, 112, 167, 182, 165, 119, 247, 217, 225,
//             71, 90, 18, 137, 63, 179, 221, 206, 95, 130, 71, 141, 130, 63, 173, 159, 46, 109, 66,
//             179, 191, 103, 147, 126, 115, 225, 137, 149, 225, 143, 159, 225, 46, 3, 122, 227, 124,
//             47, 104, 70, 225, 149, 169, 134, 134, 172, 108, 64, 91, 176, 112, 227, 209, 69, 234,
//             67, 38, 135, 139, 225, 18, 154, 66, 219, 239, 120, 247, 160, 23, 26, 243, 99, 64, 237,
//             91, 61, 206, 153, 203, 95, 226, 97, 33, 149, 251, 200, 247, 216, 87, 211, 221, 64, 4,
//             219, 135, 154, 105, 155, 39, 178, 237, 67, 87, 188, 223, 10, 14, 201, 199, 203, 27,
//             198, 1, 67, 20, 113, 165, 8, 243, 183, 167, 190, 98, 63, 67, 40, 56, 29, 202, 91, 130,
//             82, 182, 1, 125, 226, 31, 143, 241, 19, 158, 119, 84, 150, 87, 174, 103, 14, 41, 91,
//             213, 1, 117, 194, 15, 191, 64, 156, 231, 255, 226, 65, 87, 174, 144, 63, 57, 0, 125,
//             202, 189, 114, 113, 186, 24, 144, 100, 49, 163, 142, 63, 127, 180, 39, 140, 150, 76,
//             98, 254, 243, 216, 130, 132, 71, 124, 23, 172, 230, 200, 234, 226, 127, 200, 231, 14,
//             211, 254, 103, 123, 59, 251, 216, 210, 167, 218, 24, 145, 131, 56, 209, 180, 29, 121,
//             121, 221, 247, 169, 2, 244, 80, 170, 94, 160, 59, 8, 249, 95, 8, 76, 251, 42, 42, 196,
//             45, 77, 242, 52, 14, 215, 67, 222, 125, 92, 120, 73, 167, 243, 129, 130, 10, 71, 78,
//             192, 31, 136, 24, 104, 97, 191, 104, 53, 187, 38, 79, 107, 49, 253, 213, 105, 219, 95,
//             174, 79, 41, 175, 231, 55, 170, 131, 150, 89, 39, 200, 176, 20, 159, 135, 91, 248, 25,
//             202, 253, 168, 85, 128, 144, 49, 109, 58, 247, 3, 6, 232, 25, 81, 148, 100, 104, 45,
//             153, 58, 1, 120, 2, 228, 207, 112, 78, 23, 255, 151, 245, 50, 40, 10, 202, 237, 194,
//             75, 120, 106, 157, 213, 174, 36, 43, 177, 214, 187, 227, 42, 122, 222, 13, 231, 142,
//             36, 55, 43, 100, 29, 92, 227, 65, 32, 109, 73, 196, 212, 173, 243, 95, 114, 100, 57,
//             37, 174, 181, 126, 106, 192, 93, 51, 131, 161, 229, 42, 123, 136, 222, 25, 243, 237,
//             12, 240, 39, 52, 59, 140, 84, 177, 57, 141, 93, 2, 246, 79, 140, 122, 161, 17, 84, 92,
//             190, 59, 26, 193, 253, 110, 140, 166, 174, 191, 6, 172, 43, 236, 128, 201, 93, 128, 30,
//             214, 111, 127, 190, 73, 58, 149, 37, 81, 126, 180, 80, 23, 80, 207, 241, 118, 159, 125,
//             214, 141, 123, 159, 143, 81, 102, 112, 123, 121, 147, 89, 185, 204, 30, 36, 19, 5, 65,
//             204, 223, 163, 122, 168, 171, 67, 152, 179, 222, 160, 119, 172, 241, 178, 153, 249,
//             114, 17, 46, 86, 117, 28, 158, 109, 170, 33, 194, 62, 7, 56, 169, 19, 231, 62, 24, 253,
//             25, 131, 213, 152, 197, 34, 104, 177, 31, 119, 176, 223, 81, 174, 6, 55, 131, 69, 227,
//             148, 134, 94, 43, 165, 244, 11, 81, 248, 115, 139, 191, 254, 6, 226, 191, 101, 202, 42,
//             196, 152, 2, 6, 126, 130, 196, 102, 215, 51, 226, 212, 248, 184, 28, 30, 182, 56, 53,
//             86, 163, 24, 14, 2, 63, 189, 52, 221, 112, 210, 201, 172, 172, 85, 4, 184, 139, 8, 22,
//             40, 205, 193, 95, 247, 37, 183, 38, 40, 244, 243, 64, 199, 159, 172, 93, 133, 233, 75,
//             132, 199, 217, 24, 96, 31, 126, 17, 195, 146, 57, 204, 85, 26, 253, 64, 177, 43, 112,
//             172, 174, 32, 19, 124, 68, 242, 223, 182, 108, 51, 101, 130, 134, 243, 87, 89, 31, 213,
//             89, 246, 215, 19, 195, 194, 173, 74, 132, 195, 227, 44, 84, 38, 199, 25, 55, 250, 150,
//             141, 178, 189, 97, 71, 250, 68, 207, 198, 131, 96, 8, 26, 103, 115, 26, 13, 64, 213,
//             225, 226, 190, 41, 245, 101, 225, 247, 213, 39, 129, 61, 95, 107, 80, 181, 63, 47, 58,
//             20, 1, 97, 181, 162, 120, 40, 62, 201, 3, 161, 197, 46, 166, 96,
//         ];

//         let packets: [u8; 1436] = [
//             69, 0, 5, 160, 22, 43, 64, 0, 95, 6, 159, 226, 118, 179, 40, 116, 192, 168, 0, 123,
//             118, 88, 226, 105, 230, 83, 76, 55, 63, 197, 136, 176, 128, 16, 16, 1, 142, 83, 0, 0,
//             1, 1, 8, 10, 2, 4, 83, 111, 145, 186, 142, 229, 206, 219, 128, 122, 192, 126, 244, 189,
//             126, 234, 229, 18, 100, 150, 104, 114, 187, 244, 222, 16, 160, 194, 133, 237, 181, 243,
//             122, 130, 2, 97, 210, 3, 117, 229, 88, 174, 176, 44, 30, 188, 160, 108, 230, 90, 222,
//             59, 235, 222, 149, 186, 129, 3, 239, 216, 88, 202, 22, 233, 110, 31, 149, 65, 61, 104,
//             255, 200, 211, 58, 114, 67, 150, 240, 124, 139, 164, 60, 3, 79, 23, 102, 111, 109, 41,
//             196, 176, 172, 95, 243, 99, 19, 112, 26, 91, 207, 0, 217, 116, 194, 136, 94, 142, 223,
//             101, 50, 228, 122, 52, 195, 8, 67, 8, 196, 236, 68, 49, 202, 185, 100, 204, 169, 52,
//             73, 9, 215, 36, 112, 24, 13, 238, 95, 156, 107, 121, 154, 219, 113, 109, 217, 19, 156,
//             162, 100, 252, 241, 107, 142, 140, 88, 122, 72, 178, 175, 236, 181, 108, 161, 112, 219,
//             85, 121, 254, 152, 233, 41, 25, 18, 146, 239, 243, 138, 10, 143, 49, 141, 83, 185, 78,
//             207, 76, 33, 73, 154, 45, 38, 40, 213, 79, 151, 238, 223, 228, 229, 44, 162, 31, 109,
//             211, 104, 86, 238, 246, 136, 6, 205, 230, 167, 209, 13, 141, 227, 10, 51, 126, 98, 107,
//             238, 80, 147, 239, 136, 79, 74, 239, 134, 204, 223, 38, 41, 21, 183, 228, 39, 58, 183,
//             209, 90, 138, 227, 71, 213, 40, 71, 135, 243, 61, 219, 1, 168, 238, 97, 210, 80, 177,
//             21, 157, 103, 241, 242, 133, 154, 111, 209, 150, 58, 27, 91, 246, 10, 235, 126, 92,
//             240, 83, 51, 10, 243, 56, 144, 212, 216, 58, 89, 36, 118, 26, 81, 45, 8, 69, 151, 246,
//             98, 249, 136, 224, 39, 17, 151, 229, 63, 229, 167, 180, 58, 238, 133, 220, 151, 216, 6,
//             18, 67, 106, 19, 208, 239, 147, 103, 15, 9, 43, 150, 138, 63, 114, 223, 39, 178, 167,
//             88, 108, 68, 137, 196, 7, 87, 67, 219, 6, 103, 89, 250, 47, 135, 80, 200, 8, 250, 86,
//             208, 92, 77, 23, 91, 54, 246, 184, 76, 97, 185, 224, 128, 94, 25, 210, 175, 183, 130,
//             106, 111, 177, 223, 57, 56, 83, 209, 66, 59, 242, 98, 138, 122, 116, 193, 193, 244,
//             188, 197, 10, 89, 249, 255, 96, 83, 134, 105, 100, 243, 102, 244, 186, 78, 101, 241,
//             22, 103, 222, 138, 249, 252, 25, 106, 170, 243, 193, 94, 209, 196, 225, 10, 55, 8, 222,
//             255, 126, 193, 64, 195, 250, 172, 222, 26, 4, 51, 133, 153, 157, 95, 74, 29, 237, 100,
//             11, 252, 198, 14, 144, 239, 178, 54, 64, 179, 148, 200, 52, 183, 155, 172, 55, 58, 106,
//             90, 42, 28, 134, 95, 15, 159, 69, 174, 0, 24, 21, 64, 41, 118, 22, 185, 172, 185, 201,
//             9, 149, 237, 195, 112, 215, 77, 178, 75, 215, 176, 122, 110, 96, 202, 184, 79, 199, 3,
//             130, 133, 16, 149, 147, 119, 24, 81, 244, 124, 107, 102, 208, 159, 138, 186, 182, 104,
//             213, 116, 65, 130, 209, 199, 234, 106, 15, 23, 203, 245, 220, 194, 228, 197, 110, 40,
//             82, 249, 10, 81, 199, 78, 73, 100, 52, 109, 144, 150, 100, 254, 55, 160, 143, 124, 223,
//             155, 215, 62, 175, 166, 226, 226, 140, 122, 126, 74, 222, 190, 66, 211, 179, 46, 116,
//             140, 72, 243, 66, 102, 141, 169, 188, 168, 78, 193, 101, 138, 156, 111, 162, 89, 229,
//             3, 102, 249, 1, 105, 60, 7, 2, 35, 78, 121, 121, 33, 4, 222, 221, 45, 238, 125, 211,
//             118, 8, 15, 226, 1, 180, 134, 42, 87, 243, 130, 175, 150, 85, 130, 6, 227, 226, 202,
//             140, 123, 121, 9, 253, 178, 31, 224, 18, 78, 87, 245, 97, 116, 10, 93, 74, 51, 125,
//             210, 57, 183, 150, 236, 47, 52, 201, 222, 252, 38, 36, 185, 66, 56, 49, 13, 5, 112,
//             167, 182, 165, 119, 247, 217, 225, 71, 90, 18, 137, 63, 179, 221, 206, 95, 130, 71,
//             141, 130, 63, 173, 159, 46, 109, 66, 179, 191, 103, 147, 126, 115, 225, 137, 149, 225,
//             143, 159, 225, 46, 3, 122, 227, 124, 47, 104, 70, 225, 149, 169, 134, 134, 172, 108,
//             64, 91, 176, 112, 227, 209, 69, 234, 67, 38, 135, 139, 225, 18, 154, 66, 219, 239, 120,
//             247, 160, 23, 26, 243, 99, 64, 237, 91, 61, 206, 153, 203, 95, 226, 97, 33, 149, 251,
//             200, 247, 216, 87, 211, 221, 64, 4, 219, 135, 154, 105, 155, 39, 178, 237, 67, 87, 188,
//             223, 10, 14, 201, 199, 203, 27, 198, 1, 67, 20, 113, 165, 8, 243, 183, 167, 190, 98,
//             63, 67, 40, 56, 29, 202, 91, 130, 82, 182, 1, 125, 226, 31, 143, 241, 19, 158, 119, 84,
//             150, 87, 174, 103, 14, 41, 91, 213, 1, 117, 194, 15, 191, 64, 156, 231, 255, 226, 65,
//             87, 174, 144, 63, 57, 0, 125, 202, 189, 114, 113, 186, 24, 144, 100, 49, 163, 142, 63,
//             127, 180, 39, 140, 150, 76, 98, 254, 243, 216, 130, 132, 71, 124, 23, 172, 230, 200,
//             234, 226, 127, 200, 231, 14, 211, 254, 103, 123, 59, 251, 216, 210, 167, 218, 24, 145,
//             131, 56, 209, 180, 29, 121, 121, 221, 247, 169, 2, 244, 80, 170, 94, 160, 59, 8, 249,
//             95, 8, 76, 251, 42, 42, 196, 45, 77, 242, 52, 14, 215, 67, 222, 125, 92, 120, 73, 167,
//             243, 129, 130, 10, 71, 78, 192, 31, 136, 24, 104, 97, 191, 104, 53, 187, 38, 79, 107,
//             49, 253, 213, 105, 219, 95, 174, 79, 41, 175, 231, 55, 170, 131, 150, 89, 39, 200, 176,
//             20, 159, 135, 91, 248, 25, 202, 253, 168, 85, 128, 144, 49, 109, 58, 247, 3, 6, 232,
//             25, 81, 148, 100, 104, 45, 153, 58, 1, 120, 2, 228, 207, 112, 78, 23, 255, 151, 245,
//             50, 40, 10, 202, 237, 194, 75, 120, 106, 157, 213, 174, 36, 43, 177, 214, 187, 227, 42,
//             122, 222, 13, 231, 142, 36, 55, 43, 100, 29, 92, 227, 65, 32, 109, 73, 196, 212, 173,
//             243, 95, 114, 100, 57, 37, 174, 181, 126, 106, 192, 93, 51, 131, 161, 229, 42, 123,
//             136, 222, 25, 243, 237, 12, 240, 39, 52, 59, 140, 84, 177, 57, 141, 93, 2, 246, 79,
//             140, 122, 161, 17, 84, 92, 190, 59, 26, 193, 253, 110, 140, 166, 174, 191, 6, 172, 43,
//             236, 128, 201, 93, 128, 30, 214, 111, 127, 190, 73, 58, 149, 37, 81, 126, 180, 80, 23,
//             80, 207, 241, 118, 159, 125, 214, 141, 123, 159, 143, 81, 102, 112, 123, 121, 147, 89,
//             185, 204, 30, 36, 19, 5, 65, 204, 223, 163, 122, 168, 171, 67, 152, 179, 222, 160, 119,
//             172, 241, 178, 153, 249, 114, 17, 46, 86, 117, 28, 158, 109, 170, 33, 194, 62, 7, 56,
//             169, 19, 231, 62, 24, 253, 25, 131, 213, 152, 197, 34, 104, 177, 31, 119, 176, 223, 81,
//             174, 6, 55, 131, 69, 227, 148, 134, 94, 43, 165, 244, 11, 81, 248, 115, 139, 191, 254,
//             6, 226, 191, 101, 202, 42, 196, 152, 2, 6, 126, 130, 196, 102, 215, 51, 226, 212, 248,
//             184, 28, 30, 182, 56, 53, 86, 163, 24, 14, 2, 63, 189, 52, 221, 112, 210, 201, 172,
//             172, 85, 4, 184, 139, 8, 22, 40, 205, 193, 95, 247, 37, 183, 38, 40, 244, 243, 64, 199,
//             159, 172, 93, 133, 233, 75, 132, 199, 217, 24, 96, 31, 126, 17, 195, 146, 57, 204, 85,
//             26, 253, 64, 177, 43, 112, 172, 174, 32, 19, 124, 68, 242, 223, 182, 108, 51, 101, 130,
//             134, 243, 87, 89, 31, 213, 89, 246, 215, 19, 195, 194, 173, 74, 132, 195, 227, 44, 84,
//             38, 199, 25, 55, 250, 150, 141, 178, 189, 97, 71, 250, 68, 207, 198, 131, 96, 8, 26,
//             103, 115, 26, 13, 64, 213, 225, 226, 190, 41, 245, 101, 225, 247, 213, 39, 129, 61, 95,
//             107, 80, 181, 63, 47, 58, 20, 1, 97, 181, 162, 120, 40, 62, 201, 3, 161,
//         ];

//         let ether_frame = parsers::ethernet_frame::EthernetFrame::new(&frames);
//         println!("Ethernet Frame: {:?}", ether_frame);

//         let packet = parsers::ipv4::Ipv4::new(&packets);
//         println!("Packet: {:?}", packet);
//     }
// }

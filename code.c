#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/sha.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t   BS_jmpBoot[3];
    uint8_t   BS_OEMName[8];
    uint16_t  BPB_BytsPerSec;
    uint8_t   BPB_SecPerClus;
    uint16_t  BPB_RsvdSecCnt;
    uint8_t   BPB_NumFATs;
    uint16_t  BPB_RootEntCnt;
    uint16_t  BPB_TotSec16;
    uint8_t   BPB_Media;
    uint16_t  BPB_FATSz16;
    uint16_t  BPB_SecPerTrk;
    uint16_t  BPB_NumHeads;
    uint32_t  BPB_HiddSec;
    uint32_t  BPB_TotSec32;
    uint32_t  BPB_FATSz32;
    uint16_t  BPB_ExtFlags;
    uint16_t  BPB_FSVer;
    uint32_t  BPB_RootClus;
    uint16_t  BPB_FSInfo;
    uint16_t  BPB_BkBootSec;
    uint8_t   BPB_Reserved[12];
    uint8_t   BS_DrvNum;
    uint8_t   BS_Reserved1;
    uint8_t   BS_BootSig;
    uint32_t  BS_VolID;
    uint8_t   BS_VolLab[11];
    uint8_t   BS_FilSysType[8];
} BootSector;

typedef struct {
    uint8_t  DIR_Name[11];
    uint8_t  DIR_Attr;
    uint8_t  DIR_NTRes;
    uint8_t  DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
} DirEntry;
#pragma pack(pop)

static uint16_t BPB_BytsPerSec;
static uint8_t  BPB_SecPerClus;
static uint16_t BPB_RsvdSecCnt;
static uint8_t  BPB_NumFATs;
static uint32_t BPB_FATSz32;
static uint32_t BPB_RootClus;
static uint64_t FirstFATOffsetBytes;
static uint64_t FirstDataOffsetBytes;
static uint32_t ClusterSizeBytes;

static void print_usage_and_exit(void) {
    fprintf(stderr,
        "Usage: ./nyufile disk <options>\n"
        "  -i                     Print the file system information.\n"
        "  -l                     List the root directory.\n"
        "  -r filename [-s sha1]  Recover a contiguous file.\n"
        "  -R filename -s sha1    Recover a possibly non-contiguous file.\n"
    );
    exit(1);
}

static void parse_boot_sector(int fd) {
    BootSector bs;
    if (pread(fd, &bs, sizeof(bs), 0) != sizeof(bs)) {
        perror("Error reading boot sector");
        exit(1);
    }
    BPB_BytsPerSec = bs.BPB_BytsPerSec;
    BPB_SecPerClus = bs.BPB_SecPerClus;
    BPB_RsvdSecCnt = bs.BPB_RsvdSecCnt;
    BPB_NumFATs    = bs.BPB_NumFATs;
    BPB_FATSz32    = bs.BPB_FATSz32;
    BPB_RootClus   = bs.BPB_RootClus;

    FirstFATOffsetBytes = (uint64_t)BPB_RsvdSecCnt * BPB_BytsPerSec;
    FirstDataOffsetBytes = ((uint64_t)BPB_RsvdSecCnt + (uint64_t)BPB_NumFATs * BPB_FATSz32) * BPB_BytsPerSec;
    ClusterSizeBytes = (uint32_t)BPB_SecPerClus * BPB_BytsPerSec;
}

static uint64_t cluster_to_offset(uint32_t cluster_num) {
    uint64_t first_data_sector = BPB_RsvdSecCnt + (uint64_t)BPB_NumFATs * BPB_FATSz32;
    uint64_t sector = first_data_sector + (uint64_t)(cluster_num - 2) * BPB_SecPerClus;
    return sector * BPB_BytsPerSec;
}

static uint32_t read_fat_entry(int fd, uint32_t cluster_num) {
    uint64_t offset = FirstFATOffsetBytes + (uint64_t)cluster_num * 4;
    uint32_t raw;
    if (pread(fd, &raw, sizeof(raw), offset) != sizeof(raw)) {
        perror("Error reading FAT entry");
        exit(1);
    }
    return raw & 0x0FFFFFFF;
}

static void write_fat_entry(int fd, uint32_t cluster_num, uint32_t value) {
    uint32_t on_disk = (value & 0x0FFFFFFF);
    uint64_t offset = FirstFATOffsetBytes + (uint64_t)cluster_num * 4;
    if (pwrite(fd, &on_disk, sizeof(on_disk), offset) != sizeof(on_disk)) {
        perror("Error writing FAT entry");
        exit(1);
    }
    uint64_t fat_size_bytes = (uint64_t)BPB_FATSz32 * BPB_BytsPerSec;
    for (uint8_t i = 1; i < BPB_NumFATs; i++) {
        uint64_t other_offset = FirstFATOffsetBytes + (uint64_t)i * fat_size_bytes + (uint64_t)cluster_num * 4;
        if (pwrite(fd, &on_disk, sizeof(on_disk), other_offset) != sizeof(on_disk)) {
            perror("Error writing second FAT copy entry");
            exit(1);
        }
    }
}

static void build_short_name(const char *filename, uint8_t out[11]) {
    memset(out, ' ', 11);
    const char *dot = strrchr(filename, '.');
    if (!dot) {
        fprintf(stderr, "Error: \"%s\" is not in 8.3 format.\n", filename);
        exit(1);
    }
    size_t name_len = dot - filename;
    size_t ext_len = strlen(dot + 1);
    if (name_len == 0 || name_len > 8 || ext_len == 0 || ext_len > 3) {
        fprintf(stderr,
            "Error: \"%s\" → name or extension too long for 8.3 (max 8 chars name, 3 chars ext).\n",
            filename);
        exit(1);
    }
    for (size_t i = 0; i < name_len; i++) {
        out[i] = toupper((unsigned char)filename[i]);
    }
    for (size_t i = 0; i < ext_len; i++) {
        out[8 + i] = toupper((unsigned char)dot[1 + i]);
    }
}

typedef struct {
    DirEntry raw;
    uint32_t parent_clus;
    uint32_t entry_index;
    uint32_t dir_offset;
} DirEntryInfo;

static size_t scan_root_dir(int fd, int skip_deleted, int skip_lfn, DirEntryInfo *entries, size_t max_entries) {
    uint32_t clus = BPB_RootClus;
    size_t found = 0;
    uint8_t *cluster_buf = malloc(ClusterSizeBytes);
    if (!cluster_buf) {
        perror("malloc");
        exit(1);
    }
    while (clus < 0x0FFFFFF8) {
        uint64_t off = cluster_to_offset(clus);
        if (pread(fd, cluster_buf, ClusterSizeBytes, off) != ClusterSizeBytes) {
            perror("Error reading root dir cluster");
            exit(1);
        }
        size_t entries_per_cluster = ClusterSizeBytes / 32;
        for (size_t i = 0; i < entries_per_cluster; i++) {
            DirEntry *de = (DirEntry *)(cluster_buf + 32 * i);
            uint8_t first = de->DIR_Name[0];
            if (first == 0x00) {
                free(cluster_buf);
                return found;
            }
            if (skip_lfn && (de->DIR_Attr & 0x0F) == 0x0F) continue;
            if (skip_deleted && first == 0xE5) continue;
            if (found < max_entries) {
                DirEntryInfo *info = &entries[found++];
                memcpy(&info->raw, de, sizeof(DirEntry));
                info->parent_clus = clus;
                info->entry_index = (uint32_t)i;
                info->dir_offset = off + 32 * i;
            }
        }
        uint32_t next = read_fat_entry(fd, clus);
        if (next >= 0x0FFFFFF8) break;
        clus = next;
    }
    free(cluster_buf);
    return found;
}

static size_t find_deleted_candidates(int fd, const uint8_t search_name[11], DirEntryInfo *candidates, size_t max_cand) {
    uint32_t clus = BPB_RootClus;
    size_t found = 0;
    uint8_t *cluster_buf = malloc(ClusterSizeBytes);
    if (!cluster_buf) {
        perror("malloc");
        exit(1);
    }
    while (clus < 0x0FFFFFF8) {
        uint64_t off = cluster_to_offset(clus);
        if (pread(fd, cluster_buf, ClusterSizeBytes, off) != ClusterSizeBytes) {
            perror("Error reading root dir cluster");
            exit(1);
        }
        size_t entries_per_cluster = ClusterSizeBytes / 32;
        for (size_t i = 0; i < entries_per_cluster; i++) {
            DirEntry *de = (DirEntry *)(cluster_buf + 32 * i);
            if (de->DIR_Name[0] != 0xE5) continue;
            if ((de->DIR_Attr & 0x0F) == 0x0F) continue;
            if (memcmp(de->DIR_Name, search_name, 11) == 0) {
                if (found < max_cand) {
                    DirEntryInfo *info = &candidates[found];
                    memcpy(&info->raw, de, sizeof(DirEntry));
                    info->parent_clus = clus;
                    info->entry_index = (uint32_t)i;
                    info->dir_offset = off + 32 * i;
                }
                found++;
            }
        }
        uint32_t next = read_fat_entry(fd, clus);
        if (next >= 0x0FFFFFF8) break;
        clus = next;
    }
    free(cluster_buf);
    return found;
}

static void do_print_info(void) {
    printf("Number of FATs = %u\n", BPB_NumFATs);
    printf("Number of bytes per sector = %u\n", BPB_BytsPerSec);
    printf("Number of sectors per cluster = %u\n", BPB_SecPerClus);
    printf("Number of reserved sectors = %u\n", BPB_RsvdSecCnt);
}

static void do_list_root(int fd) {
    DirEntryInfo *entries = calloc(1024, sizeof(DirEntryInfo));
    if (!entries) {
        perror("calloc");
        exit(1);
    }
    size_t count = scan_root_dir(fd, 1, 1, entries, 1024);
    for (size_t i = 0; i < count; i++) {
        DirEntry *de = &entries[i].raw;
        char name[12] = {0};
        if (de->DIR_Attr & 0x10) {
            for (int j = 0; j < 8; j++) {
                if (de->DIR_Name[j] == ' ') break;
                name[j] = de->DIR_Name[j];
            }
            printf("%s/ (starting cluster = %u)\n", name,
                   ((uint32_t)de->DIR_FstClusHI << 16) | de->DIR_FstClusLO);
        } else {
            int idx = 0;
            for (int j = 0; j < 8; j++) {
                if (de->DIR_Name[j] == ' ') break;
                name[idx++] = de->DIR_Name[j];
            }
            char ext[4] = {0};
            int eidx = 0;
            for (int j = 8; j < 11; j++) {
                if (de->DIR_Name[j] == ' ') break;
                ext[eidx++] = de->DIR_Name[j];
            }
            if (eidx > 0) {
                name[idx++] = '.';
                memcpy(name + idx, ext, eidx);
                idx += eidx;
            }
            name[idx] = '\0';
            uint32_t fsz = de->DIR_FileSize;
            uint32_t fclus = ((uint32_t)de->DIR_FstClusHI << 16) | de->DIR_FstClusLO;
            if (fsz > 0) {
                printf("%s (size = %u, starting cluster = %u)\n", name, fsz, fclus);
            } else {
                printf("%s (size = 0)\n", name);
            }
        }
    }
    printf("Total number of entries = %zu\n", count);
    free(entries);
}

static uint8_t *read_entire_chain(int fd, uint32_t start_clus, uint32_t file_size) {
    if (file_size == 0) return calloc(1, 1);
    uint8_t *buf = malloc(file_size);
    if (!buf) {
        perror("malloc");
        exit(1);
    }
    uint32_t bytes_left = file_size;
    uint32_t cur = start_clus;
    uint32_t offset_in_buf = 0;
    while (cur < 0x0FFFFFF8 && bytes_left > 0) {
        uint64_t off = cluster_to_offset(cur);
        uint32_t to_read = (bytes_left > ClusterSizeBytes) ? ClusterSizeBytes : bytes_left;
        if (pread(fd, buf + offset_in_buf, to_read, off) != to_read) {
            perror("Error reading file cluster data");
            exit(1);
        }
        bytes_left -= to_read;
        offset_in_buf += to_read;
        if (bytes_left == 0) break;
        cur = read_fat_entry(fd, cur);
    }
    return buf;
}

static uint32_t write_contiguous_chain(int fd, uint32_t start_clus, uint32_t file_size) {
    if (file_size == 0) return 0;
    uint32_t needed = (file_size + ClusterSizeBytes - 1) / ClusterSizeBytes;
    for (uint32_t i = 0; i < needed; i++) {
        uint32_t this_clus = start_clus + i;
        uint32_t next_clus = (i + 1 == needed) ? 0x0FFFFFFF : (this_clus + 1);
        write_fat_entry(fd, this_clus, next_clus);
    }
    return needed;
}

static void do_recover_contiguous(int fd, const char *filename, const char *sha1_hex) {
    uint8_t search_name[11];
    build_short_name(filename, search_name);
    search_name[0] = 0xE5;

    DirEntryInfo *cands = calloc(16, sizeof(DirEntryInfo));
    if (!cands) {
        perror("calloc");
        exit(1);
    }
    size_t found = find_deleted_candidates(fd, search_name, cands, 16);

    if (!sha1_hex) {
        if (found == 0) {
            printf("%s: file not found\n", filename);
            free(cands);
            return;
        }
        if (found > 1) {
            printf("%s: multiple candidates found\n", filename);
            free(cands);
            return;
        }
        DirEntryInfo *info = &cands[0];
        DirEntry *de = &info->raw;
        uint32_t first_clus = ((uint32_t)de->DIR_FstClusHI << 16) | de->DIR_FstClusLO;
        uint32_t filesize = de->DIR_FileSize;
        char orig_char = toupper((unsigned char)filename[0]);
        if (pwrite(fd, &orig_char, 1, info->dir_offset) != 1) {
            perror("Error restoring directory entry first byte");
            exit(1);
        }
        write_contiguous_chain(fd, first_clus, filesize);
        printf("%s: successfully recovered\n", filename);
        free(cands);
        return;
    }

    unsigned char target_hash[SHA_DIGEST_LENGTH];
    if (strlen(sha1_hex) != 40) {
        fprintf(stderr, "Error: SHA-1 must be 40 hex digits.\n");
        free(cands);
        exit(1);
    }
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        unsigned int byte;
        if (sscanf(sha1_hex + 2*i, "%02x", &byte) != 1) {
            fprintf(stderr, "Error: invalid SHA-1 hex string.\n");
            free(cands);
            exit(1);
        }
        target_hash[i] = (unsigned char)byte;
    }

    size_t match_index = (size_t)-1;
    for (size_t idx = 0; idx < found; idx++) {
        DirEntryInfo *info = &cands[idx];
        DirEntry *de = &info->raw;
        uint32_t first_clus = ((uint32_t)de->DIR_FstClusHI << 16) | de->DIR_FstClusLO;
        uint32_t filesize = de->DIR_FileSize;
        uint8_t *data = read_entire_chain(fd, first_clus, filesize);
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(data, filesize, hash);
        free(data);
        if (memcmp(hash, target_hash, SHA_DIGEST_LENGTH) == 0) {
            match_index = idx;
            break;
        }
    }

    if (match_index == (size_t)-1) {
        printf("%s: file not found\n", filename);
        free(cands);
        return;
    }
    DirEntryInfo *info = &cands[match_index];
    DirEntry *de = &info->raw;
    uint32_t first_clus = ((uint32_t)de->DIR_FstClusHI << 16) | de->DIR_FstClusLO;
    uint32_t filesize = de->DIR_FileSize;
    char orig_char = toupper((unsigned char)filename[0]);
    if (pwrite(fd, &orig_char, 1, info->dir_offset) != 1) {
        perror("Error restoring directory entry first byte");
        exit(1);
    }
    write_contiguous_chain(fd, first_clus, filesize);
    printf("%s: successfully recovered with SHA-1\n", filename);
    free(cands);
}

static int compare_uint32(const void *a, const void *b) {
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    return (ia < ib) ? -1 : (ia > ib) ? 1 : 0;
}

static void swap32(uint32_t *arr, size_t i, size_t j) {
    uint32_t tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
}

static int permute_k(uint32_t *pool, size_t pool_size,
                     uint32_t *sequence, size_t k,
                     size_t depth,
                     int (*cb)(const uint32_t *, size_t, void *),
                     void *cb_arg) {
    if (depth == k) {
        return cb(sequence, k, cb_arg);
    }
    for (size_t i = depth; i < pool_size; i++) {
        swap32(pool, depth, i);
        sequence[depth] = pool[depth];
        if (permute_k(pool, pool_size, sequence, k, depth + 1, cb, cb_arg)) {
            return 1;
        }
        swap32(pool, depth, i);
    }
    return 0;
}

typedef struct {
    int fd;
    uint32_t file_size;
    unsigned char target_hash[SHA_DIGEST_LENGTH];
    uint32_t found_sequence[5];
    size_t found_n;
    int found;
} PermuteArg;

static int test_sequence(const uint32_t *seq, size_t k, void *arg) {
    PermuteArg *pa = (PermuteArg *)arg;
    uint32_t filesize = pa->file_size;
    uint8_t *buf = malloc(filesize);
    if (!buf) {
        perror("malloc");
        exit(1);
    }
    uint32_t bytes_left = filesize;
    size_t offset = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t off = cluster_to_offset(seq[i]);
        uint32_t to_read = (bytes_left > ClusterSizeBytes) ? ClusterSizeBytes : bytes_left;
        if (pread(pa->fd, buf + offset, to_read, off) != to_read) {
            perror("Error reading cluster in permute callback");
            free(buf);
            exit(1);
        }
        bytes_left -= to_read;
        offset += to_read;
        if (bytes_left == 0) break;
    }
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(buf, filesize, hash);
    free(buf);
    if (memcmp(hash, pa->target_hash, SHA_DIGEST_LENGTH) == 0) {
        memcpy(pa->found_sequence, seq, sizeof(uint32_t) * k);
        pa->found_n = k;
        pa->found = 1;
        return 1;
    }
    return 0;
}

static void do_recover_noncontiguous(int fd, const char *filename, const char *sha1_hex) {
    uint8_t search_name[11];
    build_short_name(filename, search_name);
    search_name[0] = 0xE5;

    DirEntryInfo *cands = calloc(16, sizeof(DirEntryInfo));
    if (!cands) {
        perror("calloc");
        exit(1);
    }
    size_t n_cand = find_deleted_candidates(fd, search_name, cands, 16);
    if (n_cand == 0) {
        printf("%s: file not found\n", filename);
        free(cands);
        return;
    }
    if (strlen(sha1_hex) != 40) {
        fprintf(stderr, "Error: SHA-1 must be 40 hex digits.\n");
        free(cands);
        exit(1);
    }
    unsigned char target_hash[SHA_DIGEST_LENGTH];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        unsigned int byte;
        if (sscanf(sha1_hex + 2*i, "%02x", &byte) != 1) {
            fprintf(stderr, "Error: invalid SHA-1 hex.\n");
            free(cands);
            exit(1);
        }
        target_hash[i] = (unsigned char)byte;
    }

    int global_found = 0;
    uint32_t final_sequence[5];
    size_t final_n = 0;
    DirEntryInfo *which_cand = NULL;

    for (size_t ci = 0; ci < n_cand && !global_found; ci++) {
        DirEntryInfo *info = &cands[ci];
        DirEntry *de = &info->raw;
        uint32_t filesize = de->DIR_FileSize;
        uint32_t nclusters = (filesize + ClusterSizeBytes - 1) / ClusterSizeBytes;
        if (nclusters == 0) {
            static const unsigned char standard_empty[SHA_DIGEST_LENGTH] = {
                0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,
                0x32,0x5b,0xbf,0xef,0x95,0x60,0x18,0x90,
                0xaf,0xd8,0x07,0x09
            };
            if (memcmp(standard_empty, target_hash, SHA_DIGEST_LENGTH) == 0) {
                global_found = 1;
                final_n = 0;
                which_cand = info;
            }
            continue;
        }
        if (nclusters > 5) continue;

        uint32_t pool[20];
        size_t pool_sz = 0;
        for (uint32_t cl = 2; cl <= 21; cl++) {
            uint32_t ent = read_fat_entry(fd, cl);
            if (ent == 0x00000000) pool[pool_sz++] = cl;
        }
        if (pool_sz < nclusters) continue;

        qsort(pool, pool_sz, sizeof(uint32_t), compare_uint32);
        PermuteArg pa;
        pa.fd = fd;
        pa.file_size = filesize;
        memcpy(pa.target_hash, target_hash, SHA_DIGEST_LENGTH);
        pa.found = 0;
        pa.found_n = 0;

        uint32_t sequence[5];
        if (permute_k(pool, pool_sz, sequence, nclusters, 0, test_sequence, &pa)) {
            global_found = 1;
            final_n = pa.found_n;
            memcpy(final_sequence, pa.found_sequence, final_n * sizeof(uint32_t));
            which_cand = info;
            break;
        }
    }

    if (!global_found) {
        printf("%s: file not found\n", filename);
        free(cands);
        return;
    }
    DirEntry *de = &which_cand->raw;
    char orig_char = toupper((unsigned char)filename[0]);
    if (pwrite(fd, &orig_char, 1, which_cand->dir_offset) != 1) {
        perror("Error restoring directory entry first byte");
        exit(1);
    }
    for (size_t i = 0; i < final_n; i++) {
        uint32_t c = final_sequence[i];
        uint32_t next = (i + 1 == final_n) ? 0x0FFFFFFF : final_sequence[i+1];
        write_fat_entry(fd, c, next);
    }
    printf("%s: successfully recovered with SHA-1\n", filename);
    free(cands);
}

int main(int argc, char *argv[]) {
    if (argc < 3) print_usage_and_exit();

    const char *disk_image = argv[1];
    int fd = open(disk_image, O_RDWR);
    if (fd < 0) {
        perror("Error opening disk image");
        return 1;
    }

    parse_boot_sector(fd);

    if (strcmp(argv[2], "-i") == 0) {
        if (argc != 3) print_usage_and_exit();
        do_print_info();
    }
    else if (strcmp(argv[2], "-l") == 0) {
        if (argc != 3) print_usage_and_exit();
        do_list_root(fd);
    }
    else if (strcmp(argv[2], "-r") == 0) {
        if (argc != 4 && argc != 6) print_usage_and_exit();
        const char *filename = argv[3];
        const char *sha1_hex = NULL;
        if (argc == 6) {
            if (strcmp(argv[4], "-s") != 0) print_usage_and_exit();
            sha1_hex = argv[5];
        }
        do_recover_contiguous(fd, filename, sha1_hex);
    }
    else if (strcmp(argv[2], "-R") == 0) {
        if (argc != 6) print_usage_and_exit();
        const char *filename = argv[3];
        if (strcmp(argv[4], "-s") != 0) print_usage_and_exit();
        const char *sha1_hex = argv[5];
        do_recover_noncontiguous(fd, filename, sha1_hex);
    }
    else {
        print_usage_and_exit();
    }

    close(fd);
    return 0;
}

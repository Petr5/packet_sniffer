#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#define SNAP_LEN 1518   // максимальная длина пакета для захвата
#define PROMISC 1       // promiscuous mode (перехват всех пакетов)
#define TIMEOUT 1000    // timeout в миллисекундах

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;
    pcap_dumper_t *dumper = (pcap_dumper_t *)args;
    printf("Captured packet #%d\n", count++);
    pcap_dump((u_char *)dumper, header, packet);  // записываем пакет в файл
}

void list_interfaces() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    printf("Available interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%s", d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }

    pcap_freealldevs(alldevs);
}

int main(int argc, char *argv[]) {
    char *dev = NULL;                 // имя устройства для захвата
    char errbuf[PCAP_ERRBUF_SIZE];    // буфер для сообщений об ошибках
    pcap_t *handle;                   // дескриптор сессии захвата
    pcap_dumper_t *dumper;            // дескриптор дампа
    char *dumpfile = "dump.pcap";     // имя файла для записи
    int count = 0;                    // количество пакетов для захвата
    int file_size = 0;                // максимальный размер файла в мегабайтах
    pcap_if_t *alldevs, *d;           // список всех доступных устройств

    static struct option long_options[] = {
        {"list-interfaces", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;

    while ((opt = getopt_long(argc, argv, "c:C:", long_options, &long_index)) != -1) {
        switch (opt) {
        case 0:
            if (strcmp("list-interfaces", long_options[long_index].name) == 0) {
                list_interfaces();
                return 0;
            }
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'C':
            file_size = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-c count] [-C file_size] [--list-interfaces] [interface]\n", argv[0]);
            return 1;
        }
    }

    // Использование переданного интерфейса
    if (optind < argc) {
        dev = argv[optind];
    } else {
        // получаем список всех доступных устройств
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return 1;
        }

        // выбираем первое доступное устройство
        if (alldevs == NULL) {
            fprintf(stderr, "No devices found\n");
            return 2;
        }
        dev = alldevs->name;
    }

    printf("Using device: %s\n", dev);

    // открываем устройство для захвата
    handle = pcap_open_live(dev, SNAP_LEN, PROMISC, TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Unable to open device %s: %s\n", dev, errbuf);
        return 3;
    }

    // открываем файл для записи
    dumper = pcap_dump_open_append(handle, dumpfile);
    if (dumper == NULL) {
        fprintf(stderr, "Unable to open dump file: %s\n", pcap_geterr(handle));
        return 4;
    }

    printf("Starting packet capture...\n");

    // начинаем захват пакетов
    int packet_count = 0;
    while (count == 0 || packet_count < count) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) {
            packet_handler((u_char *)dumper, header, packet);
            packet_count++;
            if (file_size > 0 && ftell(pcap_dump_file(dumper)) > file_size * 1000000) {
                pcap_dump_close(dumper);
                char new_dumpfile[256];
                snprintf(new_dumpfile, sizeof(new_dumpfile), "dump_%d.pcap", packet_count);
                dumper = pcap_dump_open(handle, new_dumpfile);
                if (dumper == NULL) {
                    fprintf(stderr, "Unable to open new dump file: %s\n", pcap_geterr(handle));
                    return 4;
                }
            }
        } else if (res == -1) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
            return 5;
        }
    }

    // закрываем дескрипторы
    pcap_dump_close(dumper);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    printf("Capture complete. Packets saved to %s\n", dumpfile);

    return 0;
}

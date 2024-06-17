#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define SNAP_LEN 1518   // максимальная длина пакета для захвата
#define PROMISC 1       // promiscuous mode (перехват всех пакетов)
#define TIMEOUT 1000    // timeout в миллисекундах

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int count = 1;
    printf("Captured packet #%d\n", count++);
    pcap_dump(args, header, packet);  // записываем пакет в файл
}

int main(int argc, char *argv[]) {
    char *dev = NULL;                 // имя устройства для захвата
    char errbuf[PCAP_ERRBUF_SIZE];    // буфер для сообщений об ошибках
    pcap_t *handle;                   // дескриптор сессии захвата
    pcap_dumper_t *dumper;            // дескриптор дампа
    char *dumpfile = "dump.pcap";     // имя файла для записи
    pcap_if_t *alldevs, *d;           // список всех доступных устройств

    // Использование переданного интерфейса
    if (argc > 1) {
        dev = argv[1];
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
    if (pcap_loop(handle, 0, packet_handler, (u_char *)dumper) < 0) {
        fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
        return 5;
    }

    // закрываем дескрипторы
    pcap_dump_close(dumper);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    printf("Capture complete. Packets saved to %s\n", dumpfile);

    return 0;
}

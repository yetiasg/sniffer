import * as cap from "cap";
import * as fs from "fs";

const { Cap, decoders } = cap;

const PROTOCOL = decoders.PROTOCOL;

class PacketSniffer {
  private cap: Cap;
  private buffer: Buffer;
  private accumulatedData: Buffer;

  constructor() {
    this.cap = new Cap();
    this.buffer = Buffer.alloc(65535); // Bufor do przechwytywania danych
    this.accumulatedData = Buffer.alloc(0); // Bufor do gromadzenia danych
  }

  public startListening(interfaceName: string, filter: string) {
    const device = Cap.findDevice(interfaceName); // Znajdź interfejs na podstawie IP
    if (!device) {
      console.error("Device not found");
      return;
    }

    const bufSize = 10 * 1024 * 1024; // Rozmiar bufora

    const linkType = this.cap.open(device, filter, bufSize, this.buffer);
    console.log({ device, linkType });

    this.cap.on("packet", (nbytes) => {
      const ethernet = decoders.Ethernet(this.buffer);
      console.log("-----------------------------------------------");

      if (ethernet.info.type === PROTOCOL.ETHERNET.IPV4) {
        const ip = ethernet.info;
        console.log(`MAC src: ${ip.srcmac}`);
        console.log(`MAC dst: ${ip.dstmac}`);

        const ipv4 = decoders.IPV4(this.buffer, ethernet.offset);
        console.log(`IP src: ${ipv4.info.srcaddr}`);
        console.log(`IP dst: ${ipv4.info.dstaddr}`);

        if (ipv4.info.protocol === PROTOCOL.IP.TCP) {
          const tcp = decoders.TCP(this.buffer, ipv4.offset);
          console.log(`PORT src: ${tcp.info.srcport}`);
          console.log(`PORT dst: ${tcp.info.dstport}`);

          // if (tcp.info.dstport === 80 || tcp.info.srcport === 80) {
          const payload = this.buffer.subarray(tcp.offset, nbytes);
          console.log(`[Payload]: ${payload}`);

          this.accumulatedData = Buffer.concat([this.accumulatedData, payload]);
          fs.writeFileSync("binary_data.bin", this.accumulatedData);
        }
      }
    });
  }
}

const packetSniffer = new PacketSniffer();
packetSniffer.startListening("192.168.88.253", "tcp");

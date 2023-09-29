package main

import(
  "fmt"
  "github.com/google/gopacket"
  //"net"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"

)

const(
  defaultSnapLen=262144
)

var(
  domains=make(map[string]int)
)

func updateConsole(){
  fmt.Print("\033[2J") // Clear the screen
	fmt.Printf("\033[HUpdating: %s", domains)
}

func PrintDomain(packet gopacket.Packet){
  ipLayer:=packet.Layer(layers.LayerTypeIPv4)
  if ipLayer!=nil{
    ip,_:=ipLayer.(*layers.IPv4)
    src:=ip.SrcIP
    dst:=ip.DstIP
   // srcip,_:=net.LookupAddr(src.String()).String()
   // dstip,_:=net.LookupAddr(dst.String()).String()
  //  domains[dstip]=domains[dstip]+1
    fmt.Println("dest: ",dst)

    fmt.Println("src: ",src)
  }
}

func main(){

  handle,err:=pcap.OpenLive("wlo1",defaultSnapLen,true,pcap.BlockForever)

  if err!=nil{
    panic(err)
  }

  defer handle.Close()

  if err:=handle.SetBPFFilter("port 80"); err !=nil{
    panic(err)
  }

  packets:=gopacket.NewPacketSource(handle,handle.LinkType()).Packets()

  for pkt:=range packets{
    PrintDomain(pkt)

}
}

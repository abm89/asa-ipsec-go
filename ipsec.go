// ipsec.go -> port from ipsec.py

package main

import (
    "encoding/csv"
    "bufio"
    "strings"
    "fmt"
    "os"
)


func main() {

    reader := bufio.NewReader(os.Stdin)
    fmt.Println("Do you have your CSVs loaded? (y/n)")
  
    for {
      fmt.Print("-> ")
      text, _ := reader.ReadString('\n')
      // convert CRLF to LF
      text = strings.Replace(text, "\n", "", -1)
  
      if strings.Compare("y", text) == 0 {
        fmt.Println("LET'S GO!!!")

    //open csv files
        localAddr, err := ReadCsv("localObjects.csv")
        if err != nil {
            panic(err)
        }
        remoteAddr, err := ReadCsv("remoteObjects.csv")
        if err != nil {
            panic(err)
        }
        vpnForm, err := ReadCsv("ipsecForm.csv")
        if err != nil {
            panic(err)
        }
        

        csvLengthLocal := len(localAddr) - 1

    //local object creation   
        for i := range localAddr  {
            if i < csvLengthLocal{
               netType := localAddr[i+1][2]
               if netType == "" {
                fmt.Println("object network", localAddr[i+1][1])
                fmt.Println("host", localAddr[i+1][0])
               } else if netType != ""{
                fmt.Println("object network", localAddr[i+1][1])
                fmt.Println("subnet", localAddr[i+1][0])
               }
               i++
            }   
        }  

        csvLengthRemote := len(remoteAddr) - 1

    //remote object creation
        for i := range remoteAddr  {
            if i < csvLengthRemote{
               netType := remoteAddr[i+1][2]
               if netType == "" {
                fmt.Println("object network", remoteAddr[i+1][1])
                fmt.Println("host", remoteAddr[i+1][0])
               } else if netType != ""{
                fmt.Println("object network", remoteAddr[i+1][1])
                fmt.Println("subnet", remoteAddr[i+1][0])
               }
               i++
            }   
        } 
        
    //Object Group Creation
        localGroupName := "VPN_" + vpnForm[1][1] + "_LOCAL"
        remoteGroupName := "VPN_" + vpnForm[1][1] + "_REMOTE"

        //local object group
        fmt.Println("object-group network", localGroupName)
        for i := range localAddr  {
            if i < csvLengthLocal{
                fmt.Println(" network-object object", localAddr[i+1][1])
               i++
            }
              
        }
        fmt.Println("exit")
        
        //remote object group
        fmt.Println("object-group network", remoteGroupName)
        for i := range remoteAddr  {
            if i < csvLengthRemote{
                fmt.Println(" network-object object", remoteAddr[i+1][1])
                i++
            }
               
        }
        fmt.Println("exit")
          
    //crypto-map ACL creation
        cmapACL := "VPN_" + vpnForm[1][1] + "_CMAP"        
        fmt.Println("access-list", cmapACL, "extended permit ip object-group", localGroupName, "object-group", remoteGroupName)

    //vpn-filter ACL creation
        filterACL := "VPN_" + vpnForm[1][1] + "_FLTR"
        fmt.Println("access-list", filterACL, "extended deny ip any any")
        
    //group-policy creation
        policyName := "VPN_"+ vpnForm[1][1] + "_POLICY"
        fmt.Println("group-policy", policyName, "internal")
        fmt.Println("group-policy", policyName, "attributes")
        fmt.Println(" vpn-filter value", filterACL)

    //determine IKE version
        ikeVer := vpnForm[1][2]
        if ikeVer == "1"{
            fmt.Println(" vpn-tunnel-protocol ikev1")
        } else if ikeVer =="2"{
            print(" vpn-tunnel-protocol ikev2")
        } else { 
            print("Invalid IKE version input")
        }

        print("exit")
        
    //tunnel-group config
        secondaryConf := false
        peerIP := vpnForm[1][3]
        secondaryIP := vpnForm[1][4]
        secret1 := "abcdefg"
        secret2 := "hijklmn"

        if secondaryIP != ""{
            secondaryConf = true
            //primary
            fmt.Println("\ntunnel-group", peerIP, "type ipsec-l2l")
            fmt.Println("tunnel-group", peerIP, "general-attributes")
            fmt.Println(" default-group-policy", policyName)
            fmt.Println("tunnel-group", peerIP, "ipsec-attributes")
            fmt.Println(" ikev1 pre-shared-key", secret1)
            fmt.Println("exit")

            //secondary
            fmt.Println("\ntunnel-group", secondaryIP, "type ipsec-l2l")
            fmt.Println("tunnel-group", secondaryIP, "general-attributes")
            fmt.Println(" default-group-policy", policyName)
            fmt.Println("tunnel-group", secondaryIP, "ipsec-attributes")
            fmt.Println(" ikev1 pre-shared-key", secret2)
            fmt.Println("exit")
        } else {
            println("\ntunnel-group", peerIP, "type ipsec-l2l")
            println("tunnel-group", peerIP, "general-attributes")
            println(" default-group-policy", policyName)
            println("tunnel-group", peerIP, "ipsec-attributes")
          
            if ikeVer == "1"{
                println(" ikev1 pre-shared-key", secret1)
                println("exit")
            } else if ikeVer =="2"{
                println(" ikev2 remote-authentication pre-shared-key", secret1)
                println(" ikev2 local-authentication pre-shared-key", secret2)
                println("exit")
            } else {
                println("something broke.")
            }

        }

    //Crypto Map Configuration
        cmapIndex := vpnForm[1][10]
        outsideMapName := vpnForm[1][11]
        p2Prop := vpnForm[1][5]
        p2Life := vpnForm[1][6]

        if ikeVer == "1" {
            ikeNegMode := vpnForm[1][9]
            println("\ncrypto map", outsideMapName, cmapIndex, "set ikev1 phase1-mode", ikeNegMode)
            println("crypto map", outsideMapName, cmapIndex, "set ikev1 transform-set", p2Prop)
        } else if ikeVer == "2" {
            println("\ncrypto map", outsideMapName, cmapIndex, "set ikev2 ipsec-proposal", p2Prop)
        } else {
            println("Invalid IKE version. Exiting...")
        }
        
        println("crypto map", outsideMapName, cmapIndex, "match address", cmapACL)
        println("crypto map", outsideMapName, cmapIndex, "set security-association lifetime seconds", p2Life)
        pfs := vpnForm[1][7]

        if pfs == "y"{
            dhGroup := "group" + vpnForm[1][8]
            println("crypto map", outsideMapName, cmapIndex, "set pfs", dhGroup)
        } else {
            println("Setting defaults...")
        }
        if secondaryConf == true {
            println("crypto map", outsideMapName, cmapIndex, "set peer", peerIP, secondaryIP)
        } else {
            println("crypto map", outsideMapName, cmapIndex, "set peer", peerIP)
        }





      } else if strings.Compare("n", text) == 0 {
          fmt.Println("Why are you here?!")
      } else {
          fmt.Println("An error as occured. Exiting...")
      }
  
    }
  
  }


// ReadCsv accepts a file and returns its content as a multi-dimentional type
// with lines and each column. Only parses to string type.
func ReadCsv(filename string) ([][]string, error) {

    // Open CSV file
    f, err := os.Open(filename)
    if err != nil {
        return [][]string{}, err
    }
    defer f.Close()

    // Read File into a Variable
    lines, err := csv.NewReader(f).ReadAll()
    if err != nil {
        return [][]string{}, err
    }

    return lines, nil
}
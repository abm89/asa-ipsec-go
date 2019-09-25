// ipsec.go -> port from ipsec.py

package main

import (
    "encoding/csv"
    "bufio"
    "strings"
    "fmt"
    "log"
    "os"

    "github.com/sethvargo/go-password/password"
)


func main() {




    reader := bufio.NewReader(os.Stdin)
    println("Do you have your CSVs loaded? (y/n)")
  
    for {
      fmt.Print("-> ")
      text, _ := reader.ReadString('\n')
      // convert CRLF to LF
      text = strings.Replace(text, "\n", "", -1)
  
      if strings.Compare("y", text) == 0 {
        println("LET'S GO!!!\n")

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
        

        csvLengthLocal := len(localAddr) - 1   //This allows for reading the CSV file and skipping the header on row 1

    //local object creation   
        for i := range localAddr  {
            if i < csvLengthLocal{
               netType := localAddr[i+1][2]
               if netType == "" {
                println("object network", localAddr[i+1][1])
                println("host", localAddr[i+1][0])
               } else if netType != ""{
                println("object network", localAddr[i+1][1])
                println("subnet", localAddr[i+1][0])
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
                println("object network", remoteAddr[i+1][1])
                println("host", remoteAddr[i+1][0])
               } else if netType != ""{
                println("object network", remoteAddr[i+1][1])
                println("subnet", remoteAddr[i+1][0])
               }
               i++
            }   
        } 
        
    //Object Group Creation
        localGroupName := "VPN_" + vpnForm[1][1] + "_LOCAL"
        remoteGroupName := "VPN_" + vpnForm[1][1] + "_REMOTE"

        //local object group
        println("object-group network", localGroupName)
        for i := range localAddr  {
            if i < csvLengthLocal{
                println(" network-object object", localAddr[i+1][1])
               i++
            }
              
        }
        println("exit")
        
        //remote object group
        println("object-group network", remoteGroupName)
        for i := range remoteAddr  {
            if i < csvLengthRemote{
                println(" network-object object", remoteAddr[i+1][1])
                i++
            }
               
        }
        println("exit")
          
    //crypto-map ACL creation
        cmapACL := "VPN_" + vpnForm[1][1] + "_CMAP"        
        println("access-list", cmapACL, "extended permit ip object-group", localGroupName, "object-group", remoteGroupName)

    //vpn-filter ACL creation
        filterACL := "VPN_" + vpnForm[1][1] + "_FLTR"
        println("access-list", filterACL, "extended deny ip any any")
        
    //group-policy creation
        policyName := "VPN_"+ vpnForm[1][1] + "_POLICY"
        println("group-policy", policyName, "internal")
        println("group-policy", policyName, "attributes")
        println(" vpn-filter value", filterACL)

    //determine IKE version
        ikeVer := vpnForm[1][2]
        if ikeVer == "1"{
            println(" vpn-tunnel-protocol ikev1")
        } else if ikeVer =="2"{
            print(" vpn-tunnel-protocol ikev2")
        } else { 
            print("Invalid IKE version input")
        }

        print("exit")
        
    //tunnel-group config
        //generate PSKs
        secret1, err := password.Generate(15, 5, 5, false, false) //Usage: (length,numbers,symbols,allow-uppercase,allow repeat characters)
        if err != nil {
            log.Fatal(err)
        }
        secret2, err := password.Generate(15, 5, 5, false, false) 
        if err != nil {
            log.Fatal(err)
        }

        secondaryConf := false
        peerIP := vpnForm[1][3]
        secondaryIP := vpnForm[1][4]


        if secondaryIP != ""{
            secondaryConf = true
            //primary
            println("\ntunnel-group", peerIP, "type ipsec-l2l")
            println("tunnel-group", peerIP, "general-attributes")
            println(" default-group-policy", policyName)
            println("tunnel-group", peerIP, "ipsec-attributes")
            println(" ikev1 pre-shared-key", secret1)
            println("exit")

            //secondary
            println("\ntunnel-group", secondaryIP, "type ipsec-l2l")
            println("tunnel-group", secondaryIP, "general-attributes")
            println(" default-group-policy", policyName)
            println("tunnel-group", secondaryIP, "ipsec-attributes")
            println(" ikev1 pre-shared-key", secret2)
            println("exit")
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

        println("\nWe're finished and done!")
        os.Exit(0)




      } else if strings.Compare("n", text) == 0 {
          println("Why are you here?!")
          os.Exit(0)
      } else {
          println("An error as occured. Exiting...")
          os.Exit(1)
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
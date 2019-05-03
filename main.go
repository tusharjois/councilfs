package main

import(
	"fmt"
	"io/ioutil"
	"github.com/tusharjois/councilfs/por"
	"time"
	"os"
	"math"
)


func main() {
    fmt.Print("Running POR test battery")
    readContents, err := ioutil.ReadFile("testFile.txt")
    if err != nil {
    	panic(err)
    }
    var proofFile *os.File;
    _, err = os.Stat("proofExecution.dat")
    if err == nil {
    	proofFile, err = os.Create("proofExecution.dat")
    	if err != nil {
    		panic(err)
    	}
    } else {
    	proofFile, err = os.OpenFile("proofExecution.dat", os.O_APPEND|os.O_WRONLY, 0600)
    	if err != nil {
    	    panic(err)
    	}
    }
    defer proofFile.Close()

    var verifyFile *os.File;
    _, err = os.Stat("verifyExecution.dat")
    if err == nil {
    	verifyFile, err = os.Create("verifyExecution.dat")
    	if err != nil {
    		panic(err)
    	}
    } else {
    	verifyFile, err = os.OpenFile("verifyExecution.txt", os.O_APPEND|os.O_WRONLY, 0600)
    	if err != nil {
    		panic(err)
    	}
    }

    defer verifyFile.Close()

    porKey := por.GenerateKey()
    var blockchainVal = make([]byte, 6)
    var seed = []byte{115,101,101,100}
    encodedSet, error := por.CreateErasureCoding(readContents, 25, 4)
    if error != nil {
        panic(error)
    }
    unitSegment := int(math.Ceil(float64(len(readContents)) / float64(((75 + 1)*10)/2))) 
    
    for k := 1; k < 100; k ++ {
        start := time.Now()
        proof := por.ProducePOR(porKey, blockchainVal, encodedSet, uint(k), seed)
        total_time := time.Since(start)
    	writeToFile := fmt.Sprintf("%v %d\n", total_time.Seconds(), k*unitSegment)
        if _, err := proofFile.WriteString(writeToFile); err != nil {
        	panic(err)
        }

        startV := time.Now()
        verify := por.VerifyPOR(encodedSet,blockchainVal, proof, uint(k))
        sVtime := time.Since(startV)
        if !verify {
        	fmt.Print("This shouldn't happen...  you need to debug")
        }
    	writeToFile = fmt.Sprintf("%v %d\n", sVtime.Seconds(), k*unitSegment)
        if _, err := verifyFile.WriteString(writeToFile); err != nil {
        	panic(err)
        }
    }
    
}
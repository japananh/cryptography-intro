package utils

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// Create a constant map
var defaultEnglishLetterFrequencies = func() map[byte]float64 {
	return map[byte]float64{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: 0, 14: 0, 15: 0, 16: 0, 17: 0, 18: 0, 19: 0, 20: 0, 21: 0, 22: 0, 23: 0, 24: 0, 25: 0, 26: 0, 27: 0, 28: 0, 29: 0, 30: 0, 31: 0, 32: 0.16516097752432846, 33: 0.0005517910120401261, 34: 5.079247809574382e-05, 35: 2.308749004351992e-06, 36: 4.617498008703984e-06, 37: 2.308749004351992e-06, 38: 0, 39: 1.6161243030463944e-05, 40: 7.618871714361573e-05, 41: 7.618871714361573e-05, 42: 3.693998406963187e-05, 43: 0, 44: 0.011786163667216918, 45: 0.0004525148048529904, 46: 0.007251780622669606, 47: 1.385249402611195e-05, 48: 4.848372909139183e-05, 49: 0.00024472739446131114, 50: 8.080621515231972e-05, 51: 5.3101227100095814e-05, 52: 3.924873307398386e-05, 53: 3.463123506527988e-05, 54: 2.77049880522239e-05, 55: 5.079247809574382e-05, 56: 3.924873307398386e-05, 57: 3.463123506527988e-05, 58: 0.0001408336892654715, 59: 0.002244104032230136, 60: 0, 61: 0, 62: 0, 63: 0.0005079247809574382, 64: 0, 65: 0.0009812183268495965, 66: 0.0005933484941184619, 67: 0.0004917635379269742, 68: 0.0003047548685744629, 69: 0.0007180209403534694, 70: 0.0004963810359356782, 71: 0.0004640585498747504, 72: 0.0007249471873665255, 73: 0.007351056829856742, 74: 0.00016392117930899143, 75: 7.157121913491175e-05, 76: 0.0003024461195701109, 77: 0.0007018596973230055, 78: 0.0003186073626005749, 79: 0.00038094358571807865, 80: 0.00041326607177900654, 81: 2.308749004351992e-06, 82: 0.0002516536414743671, 83: 0.0008080621515231971, 84: 0.0015029956018331467, 85: 0.00015699493229593545, 86: 0.00010158495619148764, 87: 0.0006649197132533736, 88: 4.617498008703984e-06, 89: 0.00037401733870502267, 90: 0, 91: 1.1543745021759959e-05, 92: 0, 93: 1.1543745021759959e-05, 94: 0, 95: 0.00019393491636556732, 96: 0, 97: 0.060766273794544426, 98: 0.011003497754741593, 99: 0.020924192226442102, 100: 0.038611518348782715, 101: 0.10568067692520808, 102: 0.019642836529026746, 103: 0.01334226049615016, 104: 0.04489131564062013, 105: 0.04938875870109781, 106: 0.0009950708208757086, 107: 0.003991827028524594, 108: 0.02907869370981334, 109: 0.02376395350179505, 110: 0.05591559213640089, 111: 0.05791035127616101, 112: 0.013743982822907407, 113: 0.0007457259284056934, 114: 0.04792962933034735, 115: 0.048070463019612826, 116: 0.06875454534960232, 117: 0.0238770822030083, 118: 0.00873861498147229, 119: 0.017006245166056772, 120: 0.0015584055779375946, 121: 0.01792743601879322, 122: 0.0004917635379269742, 123: 0, 124: 0, 125: 0, 126: 0, 127: 0}
}

const epsilon = 1e-10 /* smallest float value such that 1.0+DBL_EPSILON != 1.0 */

func IsEqualFloat(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}

func getByteFrequency(b byte, data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := 0
	for _, item := range data {
		if item == b {
			freq++
		}
	}

	return float64(freq) / float64(len(data))
}

func FrequencyScore(data []byte, englishLetterFreqs map[byte]float64) float64 {
	if englishLetterFreqs == nil || len(englishLetterFreqs) == 0 {
		englishLetterFreqs = defaultEnglishLetterFrequencies()
	}
	if len(data) == 0 {
		return 0.0
	}

	score := 0.0

	for c, freqExpected := range englishLetterFreqs {
		freqActual := getByteFrequency(c, data)
		diff := math.Abs(freqExpected - freqActual)
		score += diff
	}

	return score
}

func ReadFileLineByLine(dirPath string, filePath string) ([]byte, error) {
	if filePath == "" {
		return nil, fmt.Errorf("error file path cannot be empty")
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory: %v", err)
	}

	// Set default directory to the current working directory
	if dirPath == "" {
		dirPath = cwd
	}

	// Change working directory to given directory path
	if err := os.Chdir(dirPath); err != nil {
		return nil, fmt.Errorf("error changing working directory: %v", err)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("error file does not exist: %v", err)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("error when closing file: %v\n", err)
		}
	}()

	// Create a byte buffer to store the file contents
	var buffer bytes.Buffer

	// Read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Append each line to the buffer
		buffer.Write(scanner.Bytes())
	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Change back to original working directory
	if err := os.Chdir(cwd); err != nil {
		return nil, fmt.Errorf("error changing working directory back: %v", cwd)
	}

	// Return the contents of the file as a slice of bytes
	return buffer.Bytes(), nil
}

func GetEnglishLetterFrequency(dirPath string, filePath string) (map[byte]float64, error) {
	if filePath == "" {
		filePath = "frequency.json"
	}

	// Get english letter frequency
	jsonData, err := ReadFileLineByLine(dirPath, filePath)
	if err != nil {
		return nil, err
	}

	englishLetterFrequencies := make(map[byte]float64)
	if err := json.Unmarshal(jsonData, &englishLetterFrequencies); err != nil {
		return nil, err
	}

	return englishLetterFrequencies, nil
}

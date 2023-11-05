package digparser

import (
	"regexp"
	"strings"
)

func ParseLine(digOutput string) []string {
	lines := strings.Split(digOutput, "\n")

	var result []string
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func GetHeader(lines []string) map[string]string {
	headerInfo := make(map[string]string)
	headerPattern := regexp.MustCompile(`opcode: (\w+), status: (\w+), id: (\d+)`)

	for _, line := range lines {
		if headerPattern.MatchString(line) {
			matches := headerPattern.FindStringSubmatch(line)
			if len(matches) == 4 {
				headerInfo["opcode"] = matches[1]
				headerInfo["status"] = matches[2]
				headerInfo["id"] = matches[3]
				break
			}
		}
	}

	return headerInfo
}

func GetAnswerSection(lines []string) map[string]string {
	answerInfo := make(map[string]string)
	answerPattern := regexp.MustCompile(`(\S+)\s+(\d+)\s+IN\s+CNAME\s+(\S+)\.`)

	for _, line := range lines {
		if answerPattern.MatchString(line) {
			matches := answerPattern.FindStringSubmatch(line)
			if len(matches) == 4 {
				answerInfo["subdomain"] = matches[1]
				answerInfo["ttl"] = matches[2]
				answerInfo["cname"] = matches[3]
				break
			}
		}
	}

	return answerInfo
}

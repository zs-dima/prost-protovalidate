package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type suiteCases map[string]map[string]struct{}

func main() {
	var harness string
	var executor string
	var expectedPath string

	flag.StringVar(&harness, "harness", "", "path to protovalidate conformance harness binary")
	flag.StringVar(&executor, "executor", "", "path to conformance executor binary")
	flag.StringVar(&expectedPath, "expected", "", "path to expected_failures.yaml")
	flag.Parse()

	if harness == "" || executor == "" || expectedPath == "" {
		failf("all of --harness, --executor, and --expected are required")
	}

	expected, err := loadExpectedFailures(expectedPath)
	if err != nil {
		failf("load expected failures: %v", err)
	}

	output, err := runHarness(harness, executor, expectedPath)
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			failf("run harness: %v", err)
		}
	}

	unexpectedPass, unexpectedFail, parseErr := parseUnexpectedCases(output)
	if parseErr != nil {
		failf("parse harness output: %v", parseErr)
	}

	removed := 0
	for suite, cases := range unexpectedPass {
		for name := range cases {
			if removeCase(expected, suite, name) {
				removed++
			}
		}
	}

	added := 0
	for suite, cases := range unexpectedFail {
		for name := range cases {
			if addCase(expected, suite, name) {
				added++
			}
		}
	}

	if err := writeExpectedFailures(expectedPath, expected); err != nil {
		failf("write expected failures: %v", err)
	}

	total := countCases(expected)
	fmt.Printf(
		"updated %s: removed=%d added=%d total=%d\n",
		expectedPath,
		removed,
		added,
		total,
	)
}

func runHarness(harness, executor, expectedPath string) (string, error) {
	cmd := exec.Command(harness, "--expected_failures", expectedPath, executor)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	err := cmd.Run()
	return stdout.String(), err
}

func parseUnexpectedCases(output string) (suiteCases, suiteCases, error) {
	unexpectedPass := make(suiteCases)
	unexpectedFail := make(suiteCases)

	var currentSuite string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case strings.HasPrefix(line, "--- FAIL: "):
			suite := strings.TrimPrefix(line, "--- FAIL: ")
			if idx := strings.Index(suite, " ("); idx >= 0 {
				suite = suite[:idx]
			}
			currentSuite = strings.TrimSpace(suite)
		case strings.HasPrefix(line, "    --- PASS: "):
			if currentSuite == "" {
				return nil, nil, fmt.Errorf("encountered PASS case without active suite: %q", line)
			}
			caseName := strings.TrimPrefix(line, "    --- PASS: ")
			addCaseToSet(unexpectedPass, currentSuite, caseName)
		case strings.HasPrefix(line, "    --- FAIL: "):
			if currentSuite == "" {
				return nil, nil, fmt.Errorf("encountered FAIL case without active suite: %q", line)
			}
			caseName := strings.TrimPrefix(line, "    --- FAIL: ")
			addCaseToSet(unexpectedFail, currentSuite, caseName)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return unexpectedPass, unexpectedFail, nil
}

func addCaseToSet(sets suiteCases, suite, caseName string) {
	if _, ok := sets[suite]; !ok {
		sets[suite] = make(map[string]struct{})
	}
	sets[suite][caseName] = struct{}{}
}

func loadExpectedFailures(path string) (suiteCases, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	out := make(suiteCases)
	var currentSuite string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			currentSuite = strings.TrimSuffix(trimmed, ":")
			if _, ok := out[currentSuite]; !ok {
				out[currentSuite] = make(map[string]struct{})
			}
			continue
		}

		if strings.HasPrefix(line, "  - ") {
			if currentSuite == "" {
				return nil, fmt.Errorf("case entry without suite header: %q", line)
			}
			raw := strings.TrimSpace(strings.TrimPrefix(line, "  - "))
			name := raw
			if unquoted, err := strconv.Unquote(raw); err == nil {
				name = unquoted
			}
			out[currentSuite][name] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func writeExpectedFailures(path string, expected suiteCases) error {
	for suite, cases := range expected {
		if len(cases) == 0 {
			delete(expected, suite)
		}
	}

	suites := make([]string, 0, len(expected))
	for suite := range expected {
		suites = append(suites, suite)
	}
	sort.Strings(suites)

	var buf strings.Builder
	for i, suite := range suites {
		buf.WriteString(suite)
		buf.WriteString(":\n")

		names := make([]string, 0, len(expected[suite]))
		for name := range expected[suite] {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			buf.WriteString("  - ")
			buf.WriteString(strconv.Quote(name))
			buf.WriteString("\n")
		}

		if i+1 < len(suites) {
			buf.WriteString("\n")
		}
	}

	return os.WriteFile(path, []byte(buf.String()), 0o644)
}

func countCases(expected suiteCases) int {
	total := 0
	for _, cases := range expected {
		total += len(cases)
	}
	return total
}

func removeCase(expected suiteCases, suite, caseName string) bool {
	cases, ok := expected[suite]
	if !ok {
		return false
	}
	if _, ok := cases[caseName]; !ok {
		return false
	}
	delete(cases, caseName)
	if len(cases) == 0 {
		delete(expected, suite)
	}
	return true
}

func addCase(expected suiteCases, suite, caseName string) bool {
	cases, ok := expected[suite]
	if !ok {
		cases = make(map[string]struct{})
		expected[suite] = cases
	}
	if _, exists := cases[caseName]; exists {
		return false
	}
	cases[caseName] = struct{}{}
	return true
}

func failf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

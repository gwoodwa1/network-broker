// Command constructorcheck prevents production code from bypassing constructors
// exposed by packages in this module.
package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type typeKey struct {
	packagePath string
	typeName    string
}

type sourceFile struct {
	path        string
	packagePath string
	parsed      *ast.File
}

func main() {
	if err := run("."); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "constructor usage check failed: %v\n", err)
		os.Exit(1)
	}
}

func run(root string) error {
	modulePath, err := readModulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}

	files, fileSet, err := parseProductionFiles(root, modulePath)
	if err != nil {
		return err
	}

	constructors := findConstructedTypes(files)
	violations := findConstructorBypasses(root, files, fileSet, constructors)
	if len(violations) == 0 {
		return nil
	}

	sort.Strings(violations)
	for _, violation := range violations {
		_, _ = fmt.Fprintln(os.Stderr, violation)
	}

	return fmt.Errorf("found %d direct struct construction(s) for types with constructors", len(violations))
}

func readModulePath(path string) (string, error) {
	// #nosec G304 -- path is the repository-local go.mod selected by this command.
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read module file: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read module file: %w", err)
	}

	return "", fmt.Errorf("module path is missing")
}

func parseProductionFiles(root, modulePath string) ([]sourceFile, *token.FileSet, error) {
	fileSet := token.NewFileSet()
	files := make([]sourceFile, 0)

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %q: %w", path, walkErr)
		}
		if shouldSkipEntry(path, entry) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}

		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
		if parseErr != nil {
			return fmt.Errorf("parse %q: %w", path, parseErr)
		}
		if ast.IsGenerated(parsed) {
			return nil
		}

		packagePath, packageErr := packagePathForFile(root, modulePath, path)
		if packageErr != nil {
			return packageErr
		}
		files = append(files, sourceFile{path: path, packagePath: packagePath, parsed: parsed})

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("discover production Go files: %w", err)
	}

	return files, fileSet, nil
}

func shouldSkipEntry(path string, entry fs.DirEntry) bool {
	if entry.IsDir() {
		name := entry.Name()
		return name == ".git" || name == "vendor" || strings.HasPrefix(name, ".")
	}

	return filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go")
}

func packagePathForFile(root, modulePath, path string) (string, error) {
	relativeDirectory, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve package for %q: %w", path, err)
	}
	if relativeDirectory == "." {
		return modulePath, nil
	}

	return modulePath + "/" + filepath.ToSlash(relativeDirectory), nil
}

func findConstructedTypes(files []sourceFile) map[typeKey]struct{} {
	constructed := make(map[typeKey]struct{})
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "New") || function.Type.Results == nil {
				continue
			}
			for _, result := range function.Type.Results.List {
				if name := localResultTypeName(result.Type); name != "" {
					constructed[typeKey{packagePath: file.packagePath, typeName: name}] = struct{}{}
				}
			}
		}
	}

	return constructed
}

func localResultTypeName(expression ast.Expr) string {
	switch result := expression.(type) {
	case *ast.Ident:
		return result.Name
	case *ast.StarExpr:
		if identifier, ok := result.X.(*ast.Ident); ok {
			return identifier.Name
		}
	default:
	}

	return ""
}

func findConstructorBypasses(
	root string,
	files []sourceFile,
	fileSet *token.FileSet,
	constructors map[typeKey]struct{},
) []string {
	violations := make([]string, 0)
	for _, file := range files {
		imports := importAliases(file.parsed)
		ast.Inspect(file.parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			selector, ok := literal.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			alias, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			packagePath, ok := imports[alias.Name]
			if !ok {
				return true
			}
			key := typeKey{packagePath: packagePath, typeName: selector.Sel.Name}
			if _, hasConstructor := constructors[key]; !hasConstructor {
				return true
			}

			position := fileSet.Position(literal.Pos())
			relativePath, err := filepath.Rel(root, position.Filename)
			if err != nil {
				relativePath = position.Filename
			}
			violations = append(violations, fmt.Sprintf(
				"%s:%d:%d: use a constructor for %s.%s",
				filepath.ToSlash(relativePath), position.Line, position.Column, alias.Name, selector.Sel.Name,
			))

			return true
		})
	}

	return violations
}

func importAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name != "." && name != "_" {
			aliases[name] = path
		}
	}

	return aliases
}

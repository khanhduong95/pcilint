package parser

import (
	"fmt"
	"strings"
)

// DefaultFactory is the default parser factory implementation.
type DefaultFactory struct {
	parsers map[string]Parser
	extMap  map[string]Parser
}

// NewFactory creates a new parser factory.
func NewFactory() *DefaultFactory {
	return &DefaultFactory{
		parsers: make(map[string]Parser),
		extMap:  make(map[string]Parser),
	}
}

// Register registers a parser with the factory.
func (f *DefaultFactory) Register(p Parser) {
	name := strings.ToLower(p.Name())
	f.parsers[name] = p

	for _, ext := range p.Extensions() {
		f.extMap[strings.ToLower(ext)] = p
	}
}

// CreateParser creates a parser for the given language.
func (f *DefaultFactory) CreateParser(language string) (Parser, error) {
	name := strings.ToLower(language)
	p, ok := f.parsers[name]
	if !ok {
		return nil, fmt.Errorf("no parser registered for language: %s", language)
	}
	return p, nil
}

// SupportedLanguages returns a list of supported language names.
func (f *DefaultFactory) SupportedLanguages() []string {
	languages := make([]string, 0, len(f.parsers))
	for name := range f.parsers {
		languages = append(languages, name)
	}
	return languages
}

// ParserForExtension returns a parser that handles the given file extension.
func (f *DefaultFactory) ParserForExtension(ext string) (Parser, bool) {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	p, ok := f.extMap[ext]
	return p, ok
}

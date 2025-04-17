package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the interface that wraps the basic logging methods.
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Fatal(msg string, keysAndValues ...interface{})
	With(keysAndValues ...interface{}) Logger
	Sync() error
}

type zapLogger struct {
	*zap.Logger
}

type Config struct {
	LogLevel    string
	LogFile     string
	Development bool
}

func (c Config) Validate() error {
	if c.LogLevel == "" {
		return fmt.Errorf("log level cannot be empty")
	}

	if _, err := zapcore.ParseLevel(c.LogLevel); err != nil {
		return fmt.Errorf("invalid log level %q: %w", c.LogLevel, err)
	}

	return nil
}

// Convert interface{} pairs to zap.Field
func interfaceToFields(keysAndValues ...interface{}) []zap.Field {
	if len(keysAndValues)%2 != 0 {
		// If odd number of arguments, add empty string as value for the last key
		keysAndValues = append(keysAndValues, "")
	}

	fields := make([]zap.Field, 0, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", keysAndValues[i])
		}
		fields = append(fields, zap.Any(key, keysAndValues[i+1]))
	}
	return fields
}

func (l *zapLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.Logger.Debug(msg, interfaceToFields(keysAndValues...)...)
}

func (l *zapLogger) Info(msg string, keysAndValues ...interface{}) {
	l.Logger.Info(msg, interfaceToFields(keysAndValues...)...)
}

func (l *zapLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.Logger.Warn(msg, interfaceToFields(keysAndValues...)...)
}

func (l *zapLogger) Error(msg string, keysAndValues ...interface{}) {
	l.Logger.Error(msg, interfaceToFields(keysAndValues...)...)
}

func (l *zapLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.Logger.Fatal(msg, interfaceToFields(keysAndValues...)...)
}

func (l *zapLogger) With(keysAndValues ...interface{}) Logger {
	return &zapLogger{l.Logger.With(interfaceToFields(keysAndValues...)...)}
}

func New(cfg Config) (Logger, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid logger configuration: %w", err)
	}

	var zapCfg zap.Config
	if cfg.Development {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}

	level, err := zapcore.ParseLevel(cfg.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log level %q: %w", cfg.LogLevel, err)
	}
	zapCfg.Level.SetLevel(level)

	if cfg.LogFile != "" {
		dir := filepath.Dir(cfg.LogFile)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create log directory %q: %w", dir, err)
		}
		zapCfg.OutputPaths = []string{cfg.LogFile, "stdout"}
		zapCfg.ErrorOutputPaths = []string{cfg.LogFile, "stderr"}
	} else {
		zapCfg.OutputPaths = []string{"stdout"}
		zapCfg.ErrorOutputPaths = []string{"stderr"}
	}

	logger, err := zapCfg.Build(zap.AddCallerSkip(1))
	if err != nil {
		return nil, fmt.Errorf("failed to build zap logger: %w", err)
	}

	return &zapLogger{logger}, nil
}

func NewNop() Logger {
	return &zapLogger{zap.NewNop()}
}

func DefaultConfig() Config {
	return Config{
		LogLevel:    "info",
		Development: false,
		LogFile:     "",
	}
}

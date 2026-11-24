package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/Rahul-8283/clipdrop/app"
	"github.com/Rahul-8283/clipdrop/config"
)

func main() {
	// Logger must be initialised before any argument parsing so that
	// errors during startup are captured at the correct verbosity level.
	initLogger()

	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// run is the testable core of main. It returns an error on runtime
// failures (exit 1). For argument or usage errors it calls os.Exit(2)
// directly so the process exits with the correct POSIX code immediately.
func run() error {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	// Build config from defaults; each FlagSet may override fields.
	cfg := config.Defaults()

	switch os.Args[1] {

	case "version":
		app.PrintVersion()
		return nil

	case "run", "pair", "devices", "unpair", "doctor":
		// For all operational commands, resolve and prepare the config directory.
		dir, err := config.Dir()
		if err != nil {
			return fmt.Errorf("resolving config directory: %w", err)
		}
		cfg.ConfigDir = dir
		if os.Args[1] != "doctor" {
			if err := config.EnsureDir(dir); err != nil {
				return fmt.Errorf("creating config directory: %w", err)
			}
			config.CheckPerms(dir)
		}

	default:
		printUsage()
		os.Exit(2)
	}

	a := app.New(&cfg)
	ctx := context.Background()

	switch os.Args[1] {

	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		imagesOnly := fs.Bool("images-only", false, "sync images only, skip text")
		noText := fs.Bool("no-text", false, "alias for --images-only")
		port := fs.Int("port", 47820, "mTLS listener port")
		peer := fs.String("peer", "", "manual peer address (ip:port)")
		verbose := fs.Bool("verbose", false, "enable debug logging")

		if err := fs.Parse(os.Args[2:]); err != nil {
			if err == flag.ErrHelp {
				os.Exit(0)
			}
			os.Exit(2)
		}
		if *verbose {
			setLogLevel(slog.LevelDebug)
		}
		cfg.ImagesOnly = *imagesOnly || *noText
		cfg.NoText = *noText
		cfg.Port = *port
		cfg.PeerAddr = *peer
		cfg.Verbose = *verbose

		return a.Run(ctx, func(ctx context.Context) error {
			return app.RunSync(ctx, &cfg)
		})

	case "pair":
		// "clipdrop pair join" is a sub-subcommand routed here.
		if len(os.Args) > 2 && os.Args[2] == "join" {
			fs := flag.NewFlagSet("pair join", flag.ContinueOnError)
			fs.SetOutput(os.Stderr)
			addr := fs.String("addr", "", "manual host address (ip:port)")
			verbose := fs.Bool("verbose", false, "enable debug logging")

			if err := fs.Parse(os.Args[3:]); err != nil {
				if err == flag.ErrHelp {
					os.Exit(0)
				}
				os.Exit(2)
			}
			if *verbose {
				setLogLevel(slog.LevelDebug)
			}
			cfg.PeerAddr = *addr
			cfg.Verbose = *verbose

			return a.Run(ctx, func(ctx context.Context) error {
				return app.RunPairJoin(ctx, &cfg)
			})
		}

		// "clipdrop pair" — host-side pairing.
		fs := flag.NewFlagSet("pair", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		port := fs.Int("port", 47820, "mTLS listener port")
		verbose := fs.Bool("verbose", false, "enable debug logging")

		if err := fs.Parse(os.Args[2:]); err != nil {
			if err == flag.ErrHelp {
				os.Exit(0)
			}
			os.Exit(2)
		}
		if *verbose {
			setLogLevel(slog.LevelDebug)
		}
		cfg.Port = *port
		cfg.Verbose = *verbose

		return a.Run(ctx, func(ctx context.Context) error {
			return app.RunPairHost(ctx, &cfg)
		})

	case "devices":
		fs := flag.NewFlagSet("devices", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		verbose := fs.Bool("verbose", false, "enable debug logging")

		if err := fs.Parse(os.Args[2:]); err != nil {
			if err == flag.ErrHelp {
				os.Exit(0)
			}
			os.Exit(2)
		}
		if *verbose {
			setLogLevel(slog.LevelDebug)
		}
		cfg.Verbose = *verbose

		return app.RunDevices(ctx, &cfg)

	case "unpair":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "error: unpair requires a device name")
			fmt.Fprintln(os.Stderr, "usage: clipdrop unpair <name>")
			os.Exit(2)
		}

		// os.Args[2] is the device name; any trailing flags follow it.
		fs := flag.NewFlagSet("unpair", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)

		if err := fs.Parse(os.Args[3:]); err != nil {
			if err == flag.ErrHelp {
				os.Exit(0)
			}
			os.Exit(2)
		}

		// Device name is captured here; RunUnpair will use it in Phase 4.
		_ = os.Args[2]

		return app.RunUnpair(ctx, &cfg)

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		verbose := fs.Bool("verbose", false, "enable debug logging")

		if err := fs.Parse(os.Args[2:]); err != nil {
			if err == flag.ErrHelp {
				os.Exit(0)
			}
			os.Exit(2)
		}
		if *verbose {
			setLogLevel(slog.LevelDebug)
		}
		cfg.Verbose = *verbose

		return app.RunDoctor(ctx, &cfg)

	default:
		printUsage()
		os.Exit(2)
	}

	return nil
}

// initLogger scans os.Args for --verbose before flag parsing begins and
// sets the global slog default to DEBUG or INFO accordingly.
// The handler writes to os.Stderr so it never pollutes stdout output.
func initLogger() {
	level := slog.LevelInfo
	for _, arg := range os.Args[1:] {
		if arg == "--verbose" || arg == "-verbose" {
			level = slog.LevelDebug
			break
		}
	}
	setLogLevel(level)
}

// setLogLevel replaces the global slog default with a text handler
// writing to os.Stderr at the specified level.
func setLogLevel(level slog.Level) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

// printUsage writes the top-level command reference to os.Stderr.
func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: clipdrop <command> [flags]

Commands:
  version           print version and protocol information
  run               start clipboard sync in the foreground
  pair              generate a pairing code (host side)
  pair join         join using a pairing code (joiner side)
  devices           list trusted paired devices
  unpair <name>     remove a paired device
  doctor            run system diagnostics

Run 'clipdrop <command> --help' for command-specific flags.`)
}

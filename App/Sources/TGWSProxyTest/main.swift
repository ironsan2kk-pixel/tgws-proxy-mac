import Foundation
import TGWSProxyCore

// Test harness: start SocksServer on port from argv.
setvbuf(stdout, nil, _IONBF, 0)
let port: UInt16 = UInt16(CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "1080") ?? 1080
let server = SocksServer()
server.onStatus = { (msg: String) in FileHandle.standardOutput.write(Data(("LOG: \(msg)\n").utf8)) }
if let err = server.start(port: port) {
    FileHandle.standardOutput.write(Data(("START_FAIL: \(err)\n").utf8))
    exit(1)
}
FileHandle.standardOutput.write(Data(("STARTED: \(port)\n").utf8))
// keep alive
RunLoop.main.run()

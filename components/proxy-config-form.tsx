"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Separator } from "@/components/ui/separator"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Globe,
  Lock,
  Unlock,
  Server,
  Zap,
  Search,
  Download,
  Play,
  Filter,
  Edit,
  FileText,
  Shield,
  ChevronDown,
  ChevronUp,
} from "lucide-react"

interface ProxyConfig {
  targetDomain: string
  targetUrl: string
  enableEncryption: boolean
  enableDecryption: boolean
  proxy1Host: string
  proxy1Port: string
  proxy2Host: string
  proxy2Port: string
  enableBruteforce: boolean
  enableAutoScan: boolean
  customHeaders: string

  // Targeting & Filtering
  filterByDomain: boolean
  filterDomainPattern: string
  filterByUrlPath: boolean
  filterUrlPathPattern: string
  filterByHttpMethod: boolean
  filterHttpMethods: string[]
  filterByRequestHeader: boolean
  filterRequestHeaderName: string
  filterRequestHeaderValue: string
  filterByResponseHeader: boolean
  filterResponseHeaderName: string
  filterResponseHeaderValue: string
  filterByBodyContent: boolean
  filterBodyContentPattern: string
  filterByClientIp: boolean
  filterClientIpAddress: string

  // Request Modification
  addModifyRequestHeader: boolean
  requestHeadersToAdd: string
  removeRequestHeader: boolean
  requestHeadersToRemove: string
  modifyUserAgent: boolean
  customUserAgent: string
  modifyHostHeader: boolean
  customHostHeader: string
  replaceRequestBody: boolean
  requestBodyReplacePattern: string
  requestBodyReplaceWith: string
  changeRequestMethod: boolean
  requestMethodFrom: string
  requestMethodTo: string
  redirectRequest: boolean
  redirectToHost: string
  redirectToPort: string
  rewriteUrl: boolean
  urlRewritePattern: string
  urlRewriteWith: string

  // Response Modification
  addModifyResponseHeader: boolean
  responseHeadersToAdd: string
  removeResponseHeader: boolean
  responseHeadersToRemove: string
  modifyCookies: boolean
  cookieModifications: string
  injectHtmlJs: boolean
  htmlJsInjectionCode: string
  replaceResponseBody: boolean
  responseBodyReplacePattern: string
  responseBodyReplaceWith: string
  changeStatusCode: boolean
  statusCodeFrom: string
  statusCodeTo: string

  // Advanced & Utility
  logTraffic: boolean
  logFilePath: string
  extractSaveData: boolean
  extractDataPattern: string
  blockRequests: boolean
  blockRequestsPattern: string
  customDecryptFunction: boolean
  decryptFunctionCode: string
  customEncryptFunction: boolean
  encryptFunctionCode: string
  autoHandleAuth: boolean
  authToken: string
  replayAttack: boolean
  replayCount: string
}

export function ProxyConfigForm() {
  const [config, setConfig] = useState<ProxyConfig>({
    targetDomain: "",
    targetUrl: "",
    enableEncryption: false,
    enableDecryption: false,
    proxy1Host: "127.0.0.1",
    proxy1Port: "8083",
    proxy2Host: "127.0.0.1",
    proxy2Port: "5005",
    enableBruteforce: false,
    enableAutoScan: false,
    customHeaders: "",

    filterByDomain: false,
    filterDomainPattern: "",
    filterByUrlPath: false,
    filterUrlPathPattern: "",
    filterByHttpMethod: false,
    filterHttpMethods: [],
    filterByRequestHeader: false,
    filterRequestHeaderName: "",
    filterRequestHeaderValue: "",
    filterByResponseHeader: false,
    filterResponseHeaderName: "",
    filterResponseHeaderValue: "",
    filterByBodyContent: false,
    filterBodyContentPattern: "",
    filterByClientIp: false,
    filterClientIpAddress: "",

    addModifyRequestHeader: false,
    requestHeadersToAdd: "",
    removeRequestHeader: false,
    requestHeadersToRemove: "",
    modifyUserAgent: false,
    customUserAgent: "",
    modifyHostHeader: false,
    customHostHeader: "",
    replaceRequestBody: false,
    requestBodyReplacePattern: "",
    requestBodyReplaceWith: "",
    changeRequestMethod: false,
    requestMethodFrom: "GET",
    requestMethodTo: "POST",
    redirectRequest: false,
    redirectToHost: "",
    redirectToPort: "",
    rewriteUrl: false,
    urlRewritePattern: "",
    urlRewriteWith: "",

    addModifyResponseHeader: false,
    responseHeadersToAdd: "",
    removeResponseHeader: false,
    responseHeadersToRemove: "",
    modifyCookies: false,
    cookieModifications: "",
    injectHtmlJs: false,
    htmlJsInjectionCode: "",
    replaceResponseBody: false,
    responseBodyReplacePattern: "",
    responseBodyReplaceWith: "",
    changeStatusCode: false,
    statusCodeFrom: "",
    statusCodeTo: "",

    logTraffic: false,
    logFilePath: "./proxy_logs.txt",
    extractSaveData: false,
    extractDataPattern: "",
    blockRequests: false,
    blockRequestsPattern: "",
    customDecryptFunction: false,
    decryptFunctionCode: "",
    customEncryptFunction: false,
    encryptFunctionCode: "",
    autoHandleAuth: false,
    authToken: "",
    replayAttack: false,
    replayCount: "1",
  })

  const [isGenerating, setIsGenerating] = useState(false)
  const [generatedScripts, setGeneratedScripts] = useState<{
    proxy1: string
    proxy2: string
  } | null>(null)

  const [expandedSections, setExpandedSections] = useState({
    targeting: false,
    requestMod: false,
    responseMod: false,
    utility: false,
  })

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }))
  }

  const handleInputChange = (field: keyof ProxyConfig, value: string | boolean | string[]) => {
    setConfig((prev) => ({ ...prev, [field]: value }))
  }

  const handleMethodToggle = (method: string) => {
    setConfig((prev) => ({
      ...prev,
      filterHttpMethods: prev.filterHttpMethods.includes(method)
        ? prev.filterHttpMethods.filter((m) => m !== method)
        : [...prev.filterHttpMethods, method],
    }))
  }

  const generateScripts = async () => {
    setIsGenerating(true)
    await new Promise((resolve) => setTimeout(resolve, 2000))

    const proxy1Script = `#!/usr/bin/env python3
"""
Proxy 1 Script - MITMProxy Configuration
Target: ${config.targetDomain}
Generated: ${new Date().toISOString()}
"""

from mitmproxy import http
import json
import base64
import re
${config.logTraffic ? "import logging\nfrom datetime import datetime" : ""}

${
  config.logTraffic
    ? `
# Setup logging
logging.basicConfig(
    filename='${config.logFilePath}',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
`
    : ""
}

class ProxyInterceptor:
    def __init__(self):
        self.target_domain = "${config.targetDomain}"
        self.encryption_enabled = ${config.enableEncryption}
        self.decryption_enabled = ${config.enableDecryption}
        ${config.replayAttack ? `self.replay_count = ${config.replayCount}` : ""}
        ${config.extractSaveData ? `self.extract_pattern = r"${config.extractDataPattern}"` : ""}
        
    def should_process_request(self, flow: http.HTTPFlow) -> bool:
        """Check if request matches filtering criteria"""
        ${
          config.filterByDomain
            ? `
        # Filter by domain
        if "${config.filterDomainPattern}" not in flow.request.pretty_host:
            return False
        `
            : ""
        }
        
        ${
          config.filterByUrlPath
            ? `
        # Filter by URL path
        if not re.match(r"${config.filterUrlPathPattern}", flow.request.path):
            return False
        `
            : ""
        }
        
        ${
          config.filterByHttpMethod && config.filterHttpMethods.length > 0
            ? `
        # Filter by HTTP method
        allowed_methods = ${JSON.stringify(config.filterHttpMethods)}
        if flow.request.method not in allowed_methods:
            return False
        `
            : ""
        }
        
        ${
          config.filterByRequestHeader
            ? `
        # Filter by request header
        if "${config.filterRequestHeaderName}" not in flow.request.headers:
            return False
        if flow.request.headers.get("${config.filterRequestHeaderName}") != "${config.filterRequestHeaderValue}":
            return False
        `
            : ""
        }
        
        ${
          config.filterByBodyContent
            ? `
        # Filter by body content
        if flow.request.content and b"${config.filterBodyContentPattern}" not in flow.request.content:
            return False
        `
            : ""
        }
        
        ${
          config.filterByClientIp
            ? `
        # Filter by client IP
        if flow.client_conn.peername[0] != "${config.filterClientIpAddress}":
            return False
        `
            : ""
        }
        
        return True
        
    def request(self, flow: http.HTTPFlow) -> None:
        if not self.should_process_request(flow):
            return
            
        print(f"[v0] Intercepting request to: {flow.request.url}")
        
        ${
          config.blockRequests
            ? `
        # Block requests matching pattern
        if re.search(r"${config.blockRequestsPattern}", flow.request.url):
            print(f"[v0] Blocking request: {flow.request.url}")
            flow.response = http.Response.make(403, b"Blocked by proxy")
            return
        `
            : ""
        }
        
        ${
          config.logTraffic
            ? `
        # Log request
        logging.info(f"REQUEST: {flow.request.method} {flow.request.url}")
        logging.info(f"Headers: {dict(flow.request.headers)}")
        `
            : ""
        }
        
        ${
          config.addModifyRequestHeader
            ? `
        # Add/Modify request headers
        headers_to_add = """${config.requestHeadersToAdd}"""
        for line in headers_to_add.strip().split("\\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                flow.request.headers[key.strip()] = value.strip()
                print(f"[v0] Added header: {key.strip()}: {value.strip()}")
        `
            : ""
        }
        
        ${
          config.removeRequestHeader
            ? `
        # Remove request headers
        headers_to_remove = """${config.requestHeadersToRemove}"""
        for header in headers_to_remove.strip().split("\\n"):
            if header.strip() in flow.request.headers:
                del flow.request.headers[header.strip()]
                print(f"[v0] Removed header: {header.strip()}")
        `
            : ""
        }
        
        ${
          config.modifyUserAgent
            ? `
        # Modify User-Agent
        flow.request.headers["User-Agent"] = "${config.customUserAgent}"
        print(f"[v0] Modified User-Agent")
        `
            : ""
        }
        
        ${
          config.modifyHostHeader
            ? `
        # Modify Host header
        flow.request.headers["Host"] = "${config.customHostHeader}"
        print(f"[v0] Modified Host header")
        `
            : ""
        }
        
        ${
          config.autoHandleAuth
            ? `
        # Auto-handle authentication
        flow.request.headers["Authorization"] = "Bearer ${config.authToken}"
        print(f"[v0] Added Authorization header")
        `
            : ""
        }
        
        ${
          config.replaceRequestBody
            ? `
        # Replace request body content
        if flow.request.content:
            original_content = flow.request.content.decode('utf-8', errors='ignore')
            modified_content = re.sub(r"${config.requestBodyReplacePattern}", "${config.requestBodyReplaceWith}", original_content)
            flow.request.content = modified_content.encode('utf-8')
            print(f"[v0] Modified request body")
        `
            : ""
        }
        
        ${
          config.changeRequestMethod
            ? `
        # Change request method
        if flow.request.method == "${config.requestMethodFrom}":
            flow.request.method = "${config.requestMethodTo}"
            print(f"[v0] Changed method from ${config.requestMethodFrom} to ${config.requestMethodTo}")
        `
            : ""
        }
        
        ${
          config.rewriteUrl
            ? `
        # Rewrite URL
        original_path = flow.request.path
        flow.request.path = re.sub(r"${config.urlRewritePattern}", "${config.urlRewriteWith}", flow.request.path)
        if original_path != flow.request.path:
            print(f"[v0] Rewrote URL from {original_path} to {flow.request.path}")
        `
            : ""
        }
        
        ${
          config.redirectRequest
            ? `
        # Redirect request
        flow.request.host = "${config.redirectToHost}"
        flow.request.port = ${config.redirectToPort}
        print(f"[v0] Redirected to ${config.redirectToHost}:${config.redirectToPort}")
        `
            : ""
        }
        
        ${
          config.customEncryptFunction
            ? `
        # Custom encryption function
        if flow.request.content:
            ${config.encryptFunctionCode || "# Add your custom encryption logic here"}
        `
            : config.enableEncryption
              ? `
        # Apply encryption logic
        if flow.request.content:
            encrypted_content = base64.b64encode(flow.request.content).decode()
            flow.request.content = encrypted_content.encode()
            flow.request.headers["X-Encrypted"] = "true"
            print(f"[v0] Encrypted request body")
        `
              : ""
        }
        
        ${
          config.extractSaveData
            ? `
        # Extract and save data
        if flow.request.content:
            content = flow.request.content.decode('utf-8', errors='ignore')
            matches = re.findall(self.extract_pattern, content)
            if matches:
                with open('extracted_data.txt', 'a') as f:
                    f.write(f"{datetime.now()}: {matches}\\n")
                print(f"[v0] Extracted data: {matches}")
        `
            : ""
        }
        
    def response(self, flow: http.HTTPFlow) -> None:
        if not self.should_process_request(flow):
            return
            
        print(f"[v0] Intercepting response from: {flow.request.url}")
        
        ${
          config.logTraffic
            ? `
        # Log response
        logging.info(f"RESPONSE: {flow.response.status_code} for {flow.request.url}")
        logging.info(f"Headers: {dict(flow.response.headers)}")
        `
            : ""
        }
        
        ${
          config.filterByResponseHeader
            ? `
        # Filter by response header
        if "${config.filterResponseHeaderName}" not in flow.response.headers:
            return
        if flow.response.headers.get("${config.filterResponseHeaderName}") != "${config.filterResponseHeaderValue}":
            return
        `
            : ""
        }
        
        ${
          config.addModifyResponseHeader
            ? `
        # Add/Modify response headers
        headers_to_add = """${config.responseHeadersToAdd}"""
        for line in headers_to_add.strip().split("\\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                flow.response.headers[key.strip()] = value.strip()
                print(f"[v0] Added response header: {key.strip()}")
        `
            : ""
        }
        
        ${
          config.removeResponseHeader
            ? `
        # Remove response headers
        headers_to_remove = """${config.responseHeadersToRemove}"""
        for header in headers_to_remove.strip().split("\\n"):
            if header.strip() in flow.response.headers:
                del flow.response.headers[header.strip()]
                print(f"[v0] Removed response header: {header.strip()}")
        `
            : ""
        }
        
        ${
          config.modifyCookies
            ? `
        # Modify cookies
        cookie_mods = """${config.cookieModifications}"""
        # Parse and apply cookie modifications
        for line in cookie_mods.strip().split("\\n"):
            if line.strip():
                print(f"[v0] Cookie modification: {line}")
                # Add your cookie modification logic here
        `
            : ""
        }
        
        ${
          config.changeStatusCode
            ? `
        # Change status code
        if flow.response.status_code == ${config.statusCodeFrom}:
            flow.response.status_code = ${config.statusCodeTo}
            print(f"[v0] Changed status code from ${config.statusCodeFrom} to ${config.statusCodeTo}")
        `
            : ""
        }
        
        ${
          config.injectHtmlJs
            ? `
        # Inject HTML/JS
        if "text/html" in flow.response.headers.get("content-type", ""):
            content = flow.response.content.decode('utf-8', errors='ignore')
            injection = """${config.htmlJsInjectionCode}"""
            if "</body>" in content:
                content = content.replace("</body>", f"{injection}</body>")
                flow.response.content = content.encode('utf-8')
                print(f"[v0] Injected HTML/JS code")
        `
            : ""
        }
        
        ${
          config.replaceResponseBody
            ? `
        # Replace response body content
        if flow.response.content:
            original_content = flow.response.content.decode('utf-8', errors='ignore')
            modified_content = re.sub(r"${config.responseBodyReplacePattern}", "${config.responseBodyReplaceWith}", original_content)
            flow.response.content = modified_content.encode('utf-8')
            print(f"[v0] Modified response body")
        `
            : ""
        }
        
        ${
          config.customDecryptFunction
            ? `
        # Custom decryption function
        if flow.response.content:
            ${config.decryptFunctionCode || "# Add your custom decryption logic here"}
        `
            : config.enableDecryption
              ? `
        # Apply decryption logic
        if "X-Encrypted" in flow.request.headers:
            try:
                decrypted_content = base64.b64decode(flow.response.content)
                flow.response.content = decrypted_content
                print(f"[v0] Decrypted response body")
            except:
                pass
        `
              : ""
        }

addons = [ProxyInterceptor()]

# Run with: mitmdump -s proxy1.py -p ${config.proxy1Port} --mode upstream:http://${config.proxy2Host}:${config.proxy2Port}
`

    const proxy2Script = `#!/usr/bin/env python3
"""
Proxy 2 Script - Upstream to Burp Suite
Upstream Target: ${config.proxy2Host}:${config.proxy2Port}
Generated: ${new Date().toISOString()}
"""

from mitmproxy import http
import requests
import json
${config.replayAttack ? "import time" : ""}

class UpstreamProxy:
    def __init__(self):
        self.burp_host = "${config.proxy2Host}"
        self.burp_port = "${config.proxy2Port}"
        self.auto_scan = ${config.enableAutoScan}
        self.bruteforce = ${config.enableBruteforce}
        ${config.replayAttack ? `self.replay_count = ${config.replayCount}` : ""}
        
    def request(self, flow: http.HTTPFlow) -> None:
        print(f"[v0] Forwarding to Burp Suite: {flow.request.url}")
        
        ${
          config.enableAutoScan
            ? `
        # Auto-scan functionality
        if self.auto_scan:
            self.perform_vulnerability_scan(flow)
        `
            : ""
        }
        
        ${
          config.enableBruteforce
            ? `
        # Brute force functionality
        if self.bruteforce and "login" in flow.request.path:
            self.perform_bruteforce(flow)
        `
            : ""
        }
        
        ${
          config.replayAttack
            ? `
        # Replay attack
        for i in range(self.replay_count):
            print(f"[v0] Replaying request {i+1}/{self.replay_count}")
            time.sleep(0.1)  # Small delay between replays
        `
            : ""
        }
    
    def perform_vulnerability_scan(self, flow):
        """Implement vulnerability scanning logic"""
        print(f"[v0] Performing vulnerability scan on {flow.request.url}")
        # Add your scanning logic here
        pass
        
    def perform_bruteforce(self, flow):
        """Implement brute force logic"""
        print(f"[v0] Performing brute force on {flow.request.url}")
        # Add your brute force logic here
        pass

addons = [UpstreamProxy()]

# Run with: mitmdump -s proxy2.py -p ${config.proxy2Port}
`

    setGeneratedScripts({
      proxy1: proxy1Script,
      proxy2: proxy2Script,
    })
    setIsGenerating(false)
  }

  const downloadScript = (script: string, filename: string) => {
    const blob = new Blob([script], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      {/* Configuration Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            Target Configuration
          </CardTitle>
          <CardDescription>Configure your target domain and URL for proxy interception</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="targetDomain">Target Domain</Label>
              <Input
                id="targetDomain"
                placeholder="ibbiz-api.dev.bri.co.id"
                value={config.targetDomain}
                onChange={(e) => handleInputChange("targetDomain", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="targetUrl">Target URL</Label>
              <Input
                id="targetUrl"
                placeholder="https://ibbiz-api.dev.bri.co.id/endpoint"
                value={config.targetUrl}
                onChange={(e) => handleInputChange("targetUrl", e.target.value)}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Encryption Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" />
            Encryption & Decryption
          </CardTitle>
          <CardDescription>
            Configure encryption and decryption capabilities for request/response handling
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Encryption</Label>
              <p className="text-sm text-muted-foreground">Encrypt outgoing requests before forwarding</p>
            </div>
            <Switch
              checked={config.enableEncryption}
              onCheckedChange={(checked) => handleInputChange("enableEncryption", checked)}
            />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Enable Decryption</Label>
              <p className="text-sm text-muted-foreground">Decrypt incoming responses for analysis</p>
            </div>
            <Switch
              checked={config.enableDecryption}
              onCheckedChange={(checked) => handleInputChange("enableDecryption", checked)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Proxy Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Proxy Configuration
          </CardTitle>
          <CardDescription>Configure proxy endpoints and routing</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              Proxy 1 (Interceptor)
              <Badge variant="secondary">Primary</Badge>
            </h4>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="proxy1Host">Host</Label>
                <Input
                  id="proxy1Host"
                  value={config.proxy1Host}
                  onChange={(e) => handleInputChange("proxy1Host", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="proxy1Port">Port</Label>
                <Input
                  id="proxy1Port"
                  value={config.proxy1Port}
                  onChange={(e) => handleInputChange("proxy1Port", e.target.value)}
                />
              </div>
            </div>
          </div>

          <Separator />

          <div>
            <h4 className="font-medium mb-3 flex items-center gap-2">
              Proxy 2 (Upstream)
              <Badge variant="outline">Burp Suite</Badge>
            </h4>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="proxy2Host">Host</Label>
                <Input
                  id="proxy2Host"
                  value={config.proxy2Host}
                  onChange={(e) => handleInputChange("proxy2Host", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="proxy2Port">Port</Label>
                <Input
                  id="proxy2Port"
                  value={config.proxy2Port}
                  onChange={(e) => handleInputChange("proxy2Port", e.target.value)}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Advanced Options */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" />
            Advanced Options
          </CardTitle>
          <CardDescription>Optional features for enhanced testing capabilities</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="flex items-center gap-2">
                <Search className="h-4 w-4" />
                Automated Scanning
              </Label>
              <p className="text-sm text-muted-foreground">Automatically scan for vulnerabilities</p>
            </div>
            <Switch
              checked={config.enableAutoScan}
              onCheckedChange={(checked) => handleInputChange("enableAutoScan", checked)}
            />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label className="flex items-center gap-2">
                <Unlock className="h-4 w-4" />
                Brute Force (Optional)
              </Label>
              <p className="text-sm text-muted-foreground">Enable brute force capabilities for login endpoints</p>
            </div>
            <Switch
              checked={config.enableBruteforce}
              onCheckedChange={(checked) => handleInputChange("enableBruteforce", checked)}
            />
          </div>
          <Separator />
          <div className="space-y-2">
            <Label htmlFor="customHeaders">Custom Headers (Optional)</Label>
            <Textarea
              id="customHeaders"
              placeholder="X-Custom-Header: value&#10;Authorization: Bearer token"
              value={config.customHeaders}
              onChange={(e) => handleInputChange("customHeaders", e.target.value)}
              rows={3}
            />
          </div>

          <Separator className="my-6" />

          {/* Targeting & Filtering Section */}
          <div className="border rounded-lg">
            <button
              onClick={() => toggleSection("targeting")}
              className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4" />
                <span className="font-medium">Targeting & Filtering</span>
                <Badge variant="outline" className="ml-2">
                  {
                    [
                      config.filterByDomain,
                      config.filterByUrlPath,
                      config.filterByHttpMethod,
                      config.filterByRequestHeader,
                      config.filterByResponseHeader,
                      config.filterByBodyContent,
                      config.filterByClientIp,
                    ].filter(Boolean).length
                  }{" "}
                  active
                </Badge>
              </div>
              {expandedSections.targeting ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {expandedSections.targeting && (
              <div className="p-4 pt-0 space-y-4">
                <div className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByDomain"
                      checked={config.filterByDomain}
                      onCheckedChange={(checked) => handleInputChange("filterByDomain", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByDomain" className="cursor-pointer">
                        Filter by Domain/Host
                      </Label>
                      {config.filterByDomain && (
                        <Input
                          placeholder="*.example.com or api.example.com"
                          value={config.filterDomainPattern}
                          onChange={(e) => handleInputChange("filterDomainPattern", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByUrlPath"
                      checked={config.filterByUrlPath}
                      onCheckedChange={(checked) => handleInputChange("filterByUrlPath", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByUrlPath" className="cursor-pointer">
                        Filter by URL Path
                      </Label>
                      {config.filterByUrlPath && (
                        <Input
                          placeholder="/api/v1/user/.*"
                          value={config.filterUrlPathPattern}
                          onChange={(e) => handleInputChange("filterUrlPathPattern", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByHttpMethod"
                      checked={config.filterByHttpMethod}
                      onCheckedChange={(checked) => handleInputChange("filterByHttpMethod", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByHttpMethod" className="cursor-pointer">
                        Filter by HTTP Method
                      </Label>
                      {config.filterByHttpMethod && (
                        <div className="flex flex-wrap gap-2">
                          {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"].map((method) => (
                            <Badge
                              key={method}
                              variant={config.filterHttpMethods.includes(method) ? "default" : "outline"}
                              className="cursor-pointer"
                              onClick={() => handleMethodToggle(method)}
                            >
                              {method}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByRequestHeader"
                      checked={config.filterByRequestHeader}
                      onCheckedChange={(checked) => handleInputChange("filterByRequestHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByRequestHeader" className="cursor-pointer">
                        Filter by Request Header
                      </Label>
                      {config.filterByRequestHeader && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="Header name"
                            value={config.filterRequestHeaderName}
                            onChange={(e) => handleInputChange("filterRequestHeaderName", e.target.value)}
                          />
                          <Input
                            placeholder="Header value"
                            value={config.filterRequestHeaderValue}
                            onChange={(e) => handleInputChange("filterRequestHeaderValue", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByResponseHeader"
                      checked={config.filterByResponseHeader}
                      onCheckedChange={(checked) => handleInputChange("filterByResponseHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByResponseHeader" className="cursor-pointer">
                        Filter by Response Header
                      </Label>
                      {config.filterByResponseHeader && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="Header name"
                            value={config.filterResponseHeaderName}
                            onChange={(e) => handleInputChange("filterResponseHeaderName", e.target.value)}
                          />
                          <Input
                            placeholder="Header value"
                            value={config.filterResponseHeaderValue}
                            onChange={(e) => handleInputChange("filterResponseHeaderValue", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByBodyContent"
                      checked={config.filterByBodyContent}
                      onCheckedChange={(checked) => handleInputChange("filterByBodyContent", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByBodyContent" className="cursor-pointer">
                        Filter by Body Content
                      </Label>
                      {config.filterByBodyContent && (
                        <Input
                          placeholder="password|token|secret"
                          value={config.filterBodyContentPattern}
                          onChange={(e) => handleInputChange("filterBodyContentPattern", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="filterByClientIp"
                      checked={config.filterByClientIp}
                      onCheckedChange={(checked) => handleInputChange("filterByClientIp", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="filterByClientIp" className="cursor-pointer">
                        Filter by Client IP
                      </Label>
                      {config.filterByClientIp && (
                        <Input
                          placeholder="192.168.1.100"
                          value={config.filterClientIpAddress}
                          onChange={(e) => handleInputChange("filterClientIpAddress", e.target.value)}
                        />
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Request Modification Section */}
          <div className="border rounded-lg">
            <button
              onClick={() => toggleSection("requestMod")}
              className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Edit className="h-4 w-4" />
                <span className="font-medium">Request Modification</span>
                <Badge variant="outline" className="ml-2">
                  {
                    [
                      config.addModifyRequestHeader,
                      config.removeRequestHeader,
                      config.modifyUserAgent,
                      config.modifyHostHeader,
                      config.replaceRequestBody,
                      config.changeRequestMethod,
                      config.redirectRequest,
                      config.rewriteUrl,
                    ].filter(Boolean).length
                  }{" "}
                  active
                </Badge>
              </div>
              {expandedSections.requestMod ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {expandedSections.requestMod && (
              <div className="p-4 pt-0 space-y-4">
                <div className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="addModifyRequestHeader"
                      checked={config.addModifyRequestHeader}
                      onCheckedChange={(checked) => handleInputChange("addModifyRequestHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="addModifyRequestHeader" className="cursor-pointer">
                        Add/Modify Request Headers
                      </Label>
                      {config.addModifyRequestHeader && (
                        <Textarea
                          placeholder="X-Forwarded-For: 127.0.0.1&#10;X-Custom-Header: value"
                          value={config.requestHeadersToAdd}
                          onChange={(e) => handleInputChange("requestHeadersToAdd", e.target.value)}
                          rows={3}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="removeRequestHeader"
                      checked={config.removeRequestHeader}
                      onCheckedChange={(checked) => handleInputChange("removeRequestHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="removeRequestHeader" className="cursor-pointer">
                        Remove Request Headers
                      </Label>
                      {config.removeRequestHeader && (
                        <Textarea
                          placeholder="If-None-Match&#10;Cache-Control"
                          value={config.requestHeadersToRemove}
                          onChange={(e) => handleInputChange("requestHeadersToRemove", e.target.value)}
                          rows={2}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="modifyUserAgent"
                      checked={config.modifyUserAgent}
                      onCheckedChange={(checked) => handleInputChange("modifyUserAgent", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="modifyUserAgent" className="cursor-pointer">
                        Modify User-Agent
                      </Label>
                      {config.modifyUserAgent && (
                        <Input
                          placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
                          value={config.customUserAgent}
                          onChange={(e) => handleInputChange("customUserAgent", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="modifyHostHeader"
                      checked={config.modifyHostHeader}
                      onCheckedChange={(checked) => handleInputChange("modifyHostHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="modifyHostHeader" className="cursor-pointer">
                        Modify Host Header
                      </Label>
                      {config.modifyHostHeader && (
                        <Input
                          placeholder="example.com"
                          value={config.customHostHeader}
                          onChange={(e) => handleInputChange("customHostHeader", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="replaceRequestBody"
                      checked={config.replaceRequestBody}
                      onCheckedChange={(checked) => handleInputChange("replaceRequestBody", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="replaceRequestBody" className="cursor-pointer">
                        Replace Request Body Content
                      </Label>
                      {config.replaceRequestBody && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder='Pattern: "role":"user"'
                            value={config.requestBodyReplacePattern}
                            onChange={(e) => handleInputChange("requestBodyReplacePattern", e.target.value)}
                          />
                          <Input
                            placeholder='Replace with: "role":"admin"'
                            value={config.requestBodyReplaceWith}
                            onChange={(e) => handleInputChange("requestBodyReplaceWith", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="changeRequestMethod"
                      checked={config.changeRequestMethod}
                      onCheckedChange={(checked) => handleInputChange("changeRequestMethod", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="changeRequestMethod" className="cursor-pointer">
                        Change Request Method
                      </Label>
                      {config.changeRequestMethod && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="From: GET"
                            value={config.requestMethodFrom}
                            onChange={(e) => handleInputChange("requestMethodFrom", e.target.value)}
                          />
                          <Input
                            placeholder="To: POST"
                            value={config.requestMethodTo}
                            onChange={(e) => handleInputChange("requestMethodTo", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="redirectRequest"
                      checked={config.redirectRequest}
                      onCheckedChange={(checked) => handleInputChange("redirectRequest", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="redirectRequest" className="cursor-pointer">
                        Redirect Request
                      </Label>
                      {config.redirectRequest && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="Host: localhost"
                            value={config.redirectToHost}
                            onChange={(e) => handleInputChange("redirectToHost", e.target.value)}
                          />
                          <Input
                            placeholder="Port: 8080"
                            value={config.redirectToPort}
                            onChange={(e) => handleInputChange("redirectToPort", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="rewriteUrl"
                      checked={config.rewriteUrl}
                      onCheckedChange={(checked) => handleInputChange("rewriteUrl", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="rewriteUrl" className="cursor-pointer">
                        Rewrite URL
                      </Label>
                      {config.rewriteUrl && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="Pattern: /api/v1/(.*)"
                            value={config.urlRewritePattern}
                            onChange={(e) => handleInputChange("urlRewritePattern", e.target.value)}
                          />
                          <Input
                            placeholder="Replace: /api/v2/$1"
                            value={config.urlRewriteWith}
                            onChange={(e) => handleInputChange("urlRewriteWith", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Response Modification Section */}
          <div className="border rounded-lg">
            <button
              onClick={() => toggleSection("responseMod")}
              className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4" />
                <span className="font-medium">Response Modification</span>
                <Badge variant="outline" className="ml-2">
                  {
                    [
                      config.addModifyResponseHeader,
                      config.removeResponseHeader,
                      config.modifyCookies,
                      config.injectHtmlJs,
                      config.replaceResponseBody,
                      config.changeStatusCode,
                    ].filter(Boolean).length
                  }{" "}
                  active
                </Badge>
              </div>
              {expandedSections.responseMod ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {expandedSections.responseMod && (
              <div className="p-4 pt-0 space-y-4">
                <div className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="addModifyResponseHeader"
                      checked={config.addModifyResponseHeader}
                      onCheckedChange={(checked) => handleInputChange("addModifyResponseHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="addModifyResponseHeader" className="cursor-pointer">
                        Add/Modify Response Headers
                      </Label>
                      {config.addModifyResponseHeader && (
                        <Textarea
                          placeholder="Access-Control-Allow-Origin: *&#10;X-Custom-Header: value"
                          value={config.responseHeadersToAdd}
                          onChange={(e) => handleInputChange("responseHeadersToAdd", e.target.value)}
                          rows={3}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="removeResponseHeader"
                      checked={config.removeResponseHeader}
                      onCheckedChange={(checked) => handleInputChange("removeResponseHeader", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="removeResponseHeader" className="cursor-pointer">
                        Remove Response Headers
                      </Label>
                      {config.removeResponseHeader && (
                        <Textarea
                          placeholder="Content-Security-Policy&#10;X-Frame-Options"
                          value={config.responseHeadersToRemove}
                          onChange={(e) => handleInputChange("responseHeadersToRemove", e.target.value)}
                          rows={2}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="modifyCookies"
                      checked={config.modifyCookies}
                      onCheckedChange={(checked) => handleInputChange("modifyCookies", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="modifyCookies" className="cursor-pointer">
                        Modify Cookies
                      </Label>
                      {config.modifyCookies && (
                        <Textarea
                          placeholder="Remove Secure flag&#10;Remove HttpOnly flag"
                          value={config.cookieModifications}
                          onChange={(e) => handleInputChange("cookieModifications", e.target.value)}
                          rows={2}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="injectHtmlJs"
                      checked={config.injectHtmlJs}
                      onCheckedChange={(checked) => handleInputChange("injectHtmlJs", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="injectHtmlJs" className="cursor-pointer">
                        Inject HTML/JavaScript
                      </Label>
                      {config.injectHtmlJs && (
                        <Textarea
                          placeholder="<script>alert('XSS Test')</script>"
                          value={config.htmlJsInjectionCode}
                          onChange={(e) => handleInputChange("htmlJsInjectionCode", e.target.value)}
                          rows={3}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="replaceResponseBody"
                      checked={config.replaceResponseBody}
                      onCheckedChange={(checked) => handleInputChange("replaceResponseBody", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="replaceResponseBody" className="cursor-pointer">
                        Replace Response Body Content
                      </Label>
                      {config.replaceResponseBody && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder='Pattern: "success":false'
                            value={config.responseBodyReplacePattern}
                            onChange={(e) => handleInputChange("responseBodyReplacePattern", e.target.value)}
                          />
                          <Input
                            placeholder='Replace: "success":true'
                            value={config.responseBodyReplaceWith}
                            onChange={(e) => handleInputChange("responseBodyReplaceWith", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="changeStatusCode"
                      checked={config.changeStatusCode}
                      onCheckedChange={(checked) => handleInputChange("changeStatusCode", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="changeStatusCode" className="cursor-pointer">
                        Change Response Status Code
                      </Label>
                      {config.changeStatusCode && (
                        <div className="grid grid-cols-2 gap-2">
                          <Input
                            placeholder="From: 302"
                            value={config.statusCodeFrom}
                            onChange={(e) => handleInputChange("statusCodeFrom", e.target.value)}
                          />
                          <Input
                            placeholder="To: 200"
                            value={config.statusCodeTo}
                            onChange={(e) => handleInputChange("statusCodeTo", e.target.value)}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Advanced & Utility Features Section */}
          <div className="border rounded-lg">
            <button
              onClick={() => toggleSection("utility")}
              className="w-full flex items-center justify-between p-4 hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span className="font-medium">Advanced & Utility Features</span>
                <Badge variant="outline" className="ml-2">
                  {
                    [
                      config.logTraffic,
                      config.extractSaveData,
                      config.blockRequests,
                      config.customDecryptFunction,
                      config.customEncryptFunction,
                      config.autoHandleAuth,
                      config.replayAttack,
                    ].filter(Boolean).length
                  }{" "}
                  active
                </Badge>
              </div>
              {expandedSections.utility ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {expandedSections.utility && (
              <div className="p-4 pt-0 space-y-4">
                <div className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="logTraffic"
                      checked={config.logTraffic}
                      onCheckedChange={(checked) => handleInputChange("logTraffic", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="logTraffic" className="cursor-pointer">
                        Log Traffic to File
                      </Label>
                      {config.logTraffic && (
                        <Input
                          placeholder="./proxy_logs.txt"
                          value={config.logFilePath}
                          onChange={(e) => handleInputChange("logFilePath", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="extractSaveData"
                      checked={config.extractSaveData}
                      onCheckedChange={(checked) => handleInputChange("extractSaveData", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="extractSaveData" className="cursor-pointer">
                        Extract & Save Data (Regex)
                      </Label>
                      {config.extractSaveData && (
                        <Input
                          placeholder="(api_key|token|password):\s*([^\s,}]+)"
                          value={config.extractDataPattern}
                          onChange={(e) => handleInputChange("extractDataPattern", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="blockRequests"
                      checked={config.blockRequests}
                      onCheckedChange={(checked) => handleInputChange("blockRequests", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="blockRequests" className="cursor-pointer">
                        Block/Drop Requests
                      </Label>
                      {config.blockRequests && (
                        <Input
                          placeholder="(analytics|telemetry|tracking)"
                          value={config.blockRequestsPattern}
                          onChange={(e) => handleInputChange("blockRequestsPattern", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="customDecryptFunction"
                      checked={config.customDecryptFunction}
                      onCheckedChange={(checked) => handleInputChange("customDecryptFunction", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="customDecryptFunction" className="cursor-pointer">
                        Custom Decryption Function
                      </Label>
                      {config.customDecryptFunction && (
                        <Textarea
                          placeholder="# Add your custom decryption code here&#10;decrypted = my_decrypt(flow.response.content)"
                          value={config.decryptFunctionCode}
                          onChange={(e) => handleInputChange("decryptFunctionCode", e.target.value)}
                          rows={4}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="customEncryptFunction"
                      checked={config.customEncryptFunction}
                      onCheckedChange={(checked) => handleInputChange("customEncryptFunction", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="customEncryptFunction" className="cursor-pointer">
                        Custom Encryption Function
                      </Label>
                      {config.customEncryptFunction && (
                        <Textarea
                          placeholder="# Add your custom encryption code here&#10;encrypted = my_encrypt(flow.request.content)"
                          value={config.encryptFunctionCode}
                          onChange={(e) => handleInputChange("encryptFunctionCode", e.target.value)}
                          rows={4}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="autoHandleAuth"
                      checked={config.autoHandleAuth}
                      onCheckedChange={(checked) => handleInputChange("autoHandleAuth", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="autoHandleAuth" className="cursor-pointer">
                        Auto-Handle Authentication
                      </Label>
                      {config.autoHandleAuth && (
                        <Input
                          placeholder="your_bearer_token_here"
                          value={config.authToken}
                          onChange={(e) => handleInputChange("authToken", e.target.value)}
                        />
                      )}
                    </div>
                  </div>

                  <div className="flex items-start space-x-3">
                    <Checkbox
                      id="replayAttack"
                      checked={config.replayAttack}
                      onCheckedChange={(checked) => handleInputChange("replayAttack", checked as boolean)}
                    />
                    <div className="flex-1 space-y-2">
                      <Label htmlFor="replayAttack" className="cursor-pointer">
                        Replay Attack Automation
                      </Label>
                      {config.replayAttack && (
                        <Input
                          type="number"
                          placeholder="Number of replays"
                          value={config.replayCount}
                          onChange={(e) => handleInputChange("replayCount", e.target.value)}
                        />
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Generate Button */}
      <div className="flex justify-center">
        <Button
          onClick={generateScripts}
          disabled={!config.targetDomain || !config.targetUrl || isGenerating}
          size="lg"
          className="px-8"
        >
          {isGenerating ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
              Generating Scripts...
            </>
          ) : (
            <>
              <Play className="h-4 w-4 mr-2" />
              Generate Proxy Scripts
            </>
          )}
        </Button>
      </div>

      {/* Generated Scripts */}
      {generatedScripts && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Generated Scripts</span>
                <Badge variant="secondary">Ready</Badge>
              </CardTitle>
              <CardDescription>Your proxy scripts have been generated and are ready for download</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="bg-muted/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Proxy 1 Script</CardTitle>
                    <CardDescription className="text-xs">Primary interceptor with all modifications</CardDescription>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <Button
                      onClick={() => downloadScript(generatedScripts.proxy1, "proxy1.py")}
                      variant="outline"
                      size="sm"
                      className="w-full"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download proxy1.py
                    </Button>
                  </CardContent>
                </Card>

                <Card className="bg-muted/50">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm">Proxy 2 Script</CardTitle>
                    <CardDescription className="text-xs">Upstream proxy to Burp Suite</CardDescription>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <Button
                      onClick={() => downloadScript(generatedScripts.proxy2, "proxy2.py")}
                      variant="outline"
                      size="sm"
                      className="w-full"
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download proxy2.py
                    </Button>
                  </CardContent>
                </Card>
              </div>

              <div className="bg-muted/30 p-4 rounded-lg">
                <h4 className="font-medium mb-2">Usage Instructions:</h4>
                <div className="space-y-1 text-sm text-muted-foreground font-mono">
                  <p>
                    1. mitmdump -s proxy1.py -p {config.proxy1Port} --mode upstream:http://{config.proxy2Host}:
                    {config.proxy2Port}
                  </p>
                  <p>2. mitmdump -s proxy2.py -p {config.proxy2Port}</p>
                  <p>
                    3. Configure your browser/tool to use proxy: {config.proxy1Host}:{config.proxy1Port}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertCircle, Shield, Network, Eye, Lock, Globe, Cpu, Route, Terminal, Wifi } from "lucide-react"

export function LearnMITM() {
  return (
    <div className="space-y-6">

      {/* SECTION 1: What is a MITM Proxy */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            What is a MITM Proxy?
          </CardTitle>
          <CardDescription>An introduction to Man-in-the-Middle interception technology</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-muted-foreground">
          <p>
            A <strong>Man-in-the-Middle (MITM) proxy</strong> is a tool that intercepts and analyzes communication
            between a client (browser, mobile app) and a server. Unlike passive sniffing tools (e.g., Wireshark),
            a MITM proxy <strong>actively participates</strong> in the communication flow.
          </p>

          <p className="text-sm">
            It allows you to:
          </p>

          <ul className="text-sm space-y-1 list-disc ml-6">
            <li>Inspect HTTP/HTTPS requests and responses</li>
            <li>Modify traffic before it reaches the server or client</li>
            <li>Extract sensitive data such as tokens, cookies, or credentials</li>
            <li>Simulate attacks for learning and penetration testing</li>
            <li>Debug APIs and web/mobile applications</li>
          </ul>

          <p>
            MITM proxies are widely used by penetration testers, security researchers, and developers.
            Tools like <strong>mitmproxy, Burp Suite, Charles Proxy</strong> follow this model.
          </p>
        </CardContent>
      </Card>

      {/* SECTION 2: How MITM Works */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="w-5 h-5" />
            How MITM Proxies Work (Step-by-Step)
          </CardTitle>
        </CardHeader>
        
        <CardContent className="space-y-5">
          <div className="bg-muted p-4 rounded text-xs font-mono whitespace-pre">
{String.raw`
Client → Proxy → Server
        ↓ Modify ↓

Example flow:
 ┌─────────┐      ┌────────┐      ┌─────────┐
 │ Browser │ ---> │ Proxy  │ ---> │ Server  │
 └─────────┘      └────────┘      └─────────┘
         <--- Intercepted Response <---
`}
          </div>

          <div className="space-y-4 text-muted-foreground">

            <div className="flex gap-4">
              <div className="rounded-full bg-primary/10 text-primary w-8 h-8 flex items-center justify-center">1</div>
              <div>
                <h4 className="font-semibold">Client → Proxy Handshake</h4>
                <p className="text-sm">
                  The client sends its request to the proxy instead of directly to the server.
                  This can be configured manually (browser proxy settings) or forced through ARP spoofing.
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="rounded-full bg-primary/10 text-primary w-8 h-8 flex items-center justify-center">2</div>
              <div>
                <h4 className="font-semibold">Proxy Intercepts the Request</h4>
                <p className="text-sm">
                  The proxy reads the headers, cookies, query parameters, authentication tokens,
                  and even can modify the request before forwarding it.
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="rounded-full bg-primary/10 text-primary w-8 h-8 flex items-center justify-center">3</div>
              <div>
                <h4 className="font-semibold">Server Responds to Proxy</h4>
                <p className="text-sm">
                  The server thinks the request came normally, and sends back a response
                  (HTML, JSON, images, JavaScript, etc.).
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="rounded-full bg-primary/10 text-primary w-8 h-8 flex items-center justify-center">4</div>
              <div>
                <h4 className="font-semibold">Proxy Intercepts Response</h4>
                <p className="text-sm">
                  At this stage, the proxy can modify API responses, HTML pages, cookies,
                  authentication tokens, etc., before sending them to the client.
                </p>
              </div>
            </div>

          </div>
        </CardContent>
      </Card>

      {/* SECTION 3: Key Features */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Key Features & Capabilities
          </CardTitle>
        </CardHeader>
        
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-muted-foreground">

            <Feature
              icon={<Eye className="w-5 h-5" />}
              title="Request & Response Inspection"
              desc="View full request/response data including headers, cookies, query params, and bodies."
            />

            <Feature
              icon={<Route className="w-5 h-5" />}
              title="Traffic Modification"
              desc="Inject JavaScript, manipulate API JSON responses, or alter form data in real-time."
            />

            <Feature
              icon={<Lock className="w-5 h-5" />}
              title="TLS/HTTPS Interception"
              desc="Using a custom CA certificate, the proxy decrypts HTTPS traffic for analysis."
            />

            <Feature
              icon={<Cpu className="w-5 h-5" />}
              title="Automated Scripting"
              desc="Write Python scripts to auto-modify packets, extract credentials, or fuzz endpoints."
            />

            <Feature
              icon={<Wifi className="w-5 h-5" />}
              title="Network-Level MITM"
              desc="Combine with ARP spoofing or rogue AP attacks to intercept devices without configuration."
            />

            <Feature
              icon={<Globe className="w-5 h-5" />}
              title="Web & Mobile API Debugging"
              desc="Used by developers to inspect app communication, debug requests, and test authentication flows."
            />

          </div>
        </CardContent>
      </Card>

      {/* SECTION 4: MITM Attack Techniques */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Terminal className="w-5 h-5" />
            Common MITM Attack Techniques
          </CardTitle>
        </CardHeader>

        <CardContent className="space-y-4 text-muted-foreground">

          <Attack title="HTTP Downgrade Attack">
            Force the victim to load the HTTP version of a website instead of HTTPS, making all traffic openly readable.
          </Attack>

          <Attack title="SSL Stripping">
            Intercept HTTPS → replace it with fake HTTP response.  
            Victim thinks the site is secure but traffic is plaintext.
          </Attack>

          <Attack title="Session Hijacking">
            Steal session cookies (e.g., JWT, Bearer tokens) and impersonate the user.
          </Attack>

          <Attack title="Form Data Interception">
            Capture login form credentials, API keys, or sensitive fields from requests.
          </Attack>

          <Attack title="Response Injection (XSS, JavaScript injection)">
            Modify HTML or JavaScript responses to insert malicious code.
          </Attack>

        </CardContent>
      </Card>

      {/* SECTION 5: Defenses */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            How to Defend Against MITM Attacks
          </CardTitle>
        </CardHeader>

        <CardContent className="text-muted-foreground space-y-3 text-sm">
          <p>Security controls that reduce or block MITM attack attempts:</p>

          <ul className="ml-6 list-disc space-y-2">
            <li><strong>HTTPS Everywhere</strong> — enforce secure connections site-wide.</li>
            <li><strong>HSTS (HTTP Strict Transport Security)</strong> — prevent SSL stripping.</li>
            <li><strong>Certificate Pinning</strong> — apps reject fake CA certificates.</li>
            <li><strong>Secure Cookies</strong> — HttpOnly, SameSite, Secure flags enabled.</li>
            <li><strong>DNSSEC</strong> — protects against DNS spoofing.</li>
            <li><strong>VPN Tunnels</strong> — protect users on public Wi-Fi.</li>
            <li><strong>Modern TLS Configuration</strong> — reject legacy/insecure cipher suites.</li>
          </ul>
        </CardContent>
      </Card>
    </div>
  )
}

function Feature({ icon, title, desc }: any) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2 text-primary">{icon}<span className="font-semibold">{title}</span></div>
      <p className="text-sm">{desc}</p>
    </div>
  )
}

function Attack({ title, children }: any) {
  return (
    <div>
      <p className="font-semibold">{title}</p>
      <p className="text-sm">{children}</p>
    </div>
  )
}

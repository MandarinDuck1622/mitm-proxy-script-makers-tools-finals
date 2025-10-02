import { Shield, Terminal } from "lucide-react"

export function Header() {
  return (
    <header className="border-b border-border bg-card">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <Terminal className="h-5 w-5 text-muted-foreground" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-foreground">MITMP</h1>
            <p className="text-sm text-muted-foreground">Security Testing Suite for MITM Proxy</p>
          </div>
        </div>
      </div>
    </header>
  )
}

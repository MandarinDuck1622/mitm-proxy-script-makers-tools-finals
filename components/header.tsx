import { Shield, Zap } from "lucide-react"

export function Header() {
  return (
    <header className="border-b border-border bg-card">
      <div className="container mx-auto px-4 py-6">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-primary" />
            <Zap className="h-6 w-6 text-yellow-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">MITMP</h1>
            <p className="text-sm text-muted-foreground">Pen Testing Man-in-the-Middle Proxy Tool</p>
          </div>
        </div>
      </div>
    </header>
  )
}

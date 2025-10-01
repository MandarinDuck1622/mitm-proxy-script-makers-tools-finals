import { ProxyConfigForm } from "@/components/proxy-config-form"
import { Header } from "@/components/header"

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-foreground mb-2">Proxy Configuration Tool</h1>
            <p className="text-muted-foreground text-lg">
              Generate custom proxy scripts for security testing and API analysis
            </p>
          </div>
          <ProxyConfigForm />
        </div>
      </main>
    </div>
  )
}

"use client"

import { ProxyConfigForm } from "@/components/proxy-config-form"
import { Header } from "@/components/header"
import { LearnMITM } from "@/components/learn-mitm"
import { QuizResources } from "@/components/quiz-resources"
import { GuidedLabs } from "@/components/guided-labs"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Code2, BookOpen, HelpCircle, Compass } from "lucide-react"
import { useState } from "react"

export default function Home() {
  const [activeTab, setActiveTab] = useState("scripting")

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-8">
        <div className="max-w-6xl mx-auto">
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full max-w-full grid-cols-4 gap-1 mb-8 h-auto p-2">
              <TabsTrigger value="scripting" className="flex flex-col items-center gap-1 text-xs p-2">
                <Code2 className="w-4 h-4" />
                <span>Scripting Tool</span>
              </TabsTrigger>
              <TabsTrigger value="labs" className="flex flex-col items-center gap-1 text-xs p-2">
                <Compass className="w-4 h-4" />
                <span>Guided Labs</span>
              </TabsTrigger>
              <TabsTrigger value="learn" className="flex flex-col items-center gap-1 text-xs p-2">
                <BookOpen className="w-4 h-4" />
                <span>Learn MITM</span>
              </TabsTrigger>
              <TabsTrigger value="quiz" className="flex flex-col items-center gap-1 text-xs p-2">
                <HelpCircle className="w-4 h-4" />
                <span>Quiz</span>
              </TabsTrigger>
            </TabsList>

            {/* Tab 1: Proxy Scripting Tool */}
            <TabsContent value="scripting" className="space-y-6">
              <div className="mb-8">
                <h1 className="text-3xl font-bold text-foreground mb-2">Scripting Tool</h1>
                <p className="text-muted-foreground text-lg">
                  Generate custom proxy scripts for security testing and API analysis
                </p>
              </div>
              <ProxyConfigForm />
            </TabsContent>

            {/* Tab 2: Guided Labs */}
            <TabsContent value="labs" className="space-y-6">
              <div className="mb-8">
                <h1 className="text-3xl font-bold text-foreground mb-2">Guided Labs</h1>
                <p className="text-muted-foreground text-lg">
                  Complete hands-on training scenarios for MITM proxy techniques
                </p>
              </div>
              <GuidedLabs />
            </TabsContent>

            
            {/* Tab 3: Learn MITM */}
            <TabsContent value="learn" className="space-y-6">
              <div className="mb-8">
                <h1 className="text-3xl font-bold text-foreground mb-2">Learn MITM</h1>
                <p className="text-muted-foreground text-lg">
                  Master the fundamentals of MITM proxy technology and its applications
                </p>
              </div>
              <LearnMITM />
            </TabsContent>

            {/* Tab 4: Quiz & Resources */}
            <TabsContent value="quiz" className="space-y-6">
              <div className="mb-8">
                <h1 className="text-3xl font-bold text-foreground mb-2">Quiz & Resources</h1>
                <p className="text-muted-foreground text-lg">
                  Test your knowledge and access additional learning materials
                </p>
              </div>
              <QuizResources />
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  )
}

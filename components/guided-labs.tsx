"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { CheckCircle2, Circle, ChevronRight, BookOpen, Play, Key } from "lucide-react"

interface Lab {
  id: number
  title: string
  description: string
  difficulty: "Beginner" | "Intermediate" | "Advanced"
  objectives: string[]
  completed: boolean
}

export function GuidedLabs() {
  const [labs, setLabs] = useState<Lab[]>([
    {
      id: 1,
      title: "Decrypting Encrypted Login Credentials (Local Demo App)",
      description:
        "Demonstrates how JavaScript-encrypted login credentials can still be decrypted and inspected by a Man-in-the-Middle proxy, while the backend continues to receive encrypted data.",
      difficulty: "Beginner",
      objectives: [
        "Run the local Flask login application on 127.0.0.1:5000",
        "Generate Proxy1 and Proxy2 scripts using the UI",
        "Route browser traffic through Proxy1 → Burp → Proxy2",
        "Observe plaintext credentials in Burp after Proxy1 decryption",
        "Confirm Proxy2 re-encrypts credentials before forwarding to the backend",
      ],
      completed: false,
    },
  ])

  const [selectedLab, setSelectedLab] = useState<number | null>(null)

  const toggleLab = (id: number) => {
    setLabs(labs.map((lab) => (lab.id === id ? { ...lab, completed: !lab.completed } : lab)))
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner":
        return "bg-green-500/20 text-green-700"
      case "Intermediate":
        return "bg-yellow-500/20 text-yellow-700"
      case "Advanced":
        return "bg-red-500/20 text-red-700"
      default:
        return "bg-gray-500/20"
    }
  }

  if (selectedLab) {
    const currentLab = labs[0]

    return (
      <div className="space-y-6">
        <Button variant="outline" onClick={() => setSelectedLab(null)}>
          Back to Labs
        </Button>

        <Card>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <CardTitle className="text-2xl mb-2">{currentLab.title}</CardTitle>
                <CardDescription className="text-base">{currentLab.description}</CardDescription>
              </div>
              <Badge className={getDifficultyColor(currentLab.difficulty)} variant="secondary">
                {currentLab.difficulty}
              </Badge>
            </div>
          </CardHeader>

          <CardContent className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <BookOpen className="w-5 h-5" />
                Learning Objectives
              </h3>
              <ul className="space-y-2">
                {currentLab.objectives.map((obj, idx) => (
                  <li key={idx} className="flex gap-3 text-muted-foreground">
                    <span className="text-primary font-bold">{idx + 1}.</span>
                    <span>{obj}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="border-t pt-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Key className="w-5 h-5" />
                Lab Instructions
              </h3>

              <div className="bg-muted/50 p-4 rounded-lg space-y-4 text-sm">
                <p className="bg-blue-500/10 border border-blue-500/30 rounded-md p-4">
                  <strong>Lab File Download:</strong>
                  <br /><br />
                  <a
                    href="/labs/html-cbc2.zip"
                    download
                    className="inline-flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition"
                  >
                    <Play className="w-4 h-4" />
                    Download Lab Files (.zip)
                  </a>
                  <br /><br />
                  Extract the ZIP contents and integrate the HTML and JavaScript files into your Flask app.
                </p>

                <p>
                  <strong>Step 0 – Prerequisites:</strong>
                  <br />• Flask demo app (<code>app.py</code>) serving <code>/register.html</code> and <code>/login.html</code>
                  <br />• Generated <code>proxy1.py</code>, <code>proxy2.py</code>, and <code>util.py</code>
                  <br />• Burp Suite or equivalent proxy
                </p>

                <p>
                  <strong>Step 1 – Integrate lab files:</strong>
                  <br />• Copy HTML files into <code>templates/</code>
                  <br />• Copy JS files into <code>static/</code>
                  <br />• Confirm JavaScript encrypts credentials before submission
                </p>

                <p>
                  <strong>Step 2 – Start the backend:</strong>
                  <br /><code>python app.py</code>
                  <br />Verify <code>http://127.0.0.1:5000/login.html</code> loads
                </p>

                <p>
                  <strong>Step 3 – Start Proxy2:</strong>
                  <br />Run <code>proxy2.py</code> (re-encrypts credentials before server)
                </p>

                <p>
                  <strong>Step 4 – Start Proxy1:</strong>
                  <br />Run <code>proxy1.py</code> upstream to Burp
                  <br />
                  <code>Browser → Proxy1 → Burp → Proxy2 → Flask</code>
                </p>

                <p>
                  <strong>Step 5 – Login and observe:</strong>
                  <br />• Enter credentials in browser
                  <br />• Observe plaintext credentials in Burp
                  <br />• Confirm encrypted payload reaches Flask backend
                </p>

                <p>
                  <strong>Step 6 – Reflection:</strong>
                  <br />
                  Client-side encryption does not protect credentials against a trusted MITM that can decrypt and
                  re-encrypt traffic.
                </p>
              </div>
            </div>

            <Button size="lg" className="w-full bg-primary" onClick={() => setSelectedLab(null)}>
              Back to Lab Selection
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Guided MITM Lab</CardTitle>
          <CardDescription>
            A hands-on guided exercise using your own encrypted login application and MITM proxy chain.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {labs.map((lab) => (
            <Card key={lab.id}>
              <CardContent className="pt-6 flex items-start gap-4">
                <button onClick={() => toggleLab(lab.id)}>
                  {lab.completed ? (
                    <CheckCircle2 className="w-6 h-6 text-green-500" />
                  ) : (
                    <Circle className="w-6 h-6 text-muted-foreground" />
                  )}
                </button>

                <div className="flex-1">
                  <h3 className="font-semibold">{lab.title}</h3>
                  <p className="text-sm text-muted-foreground mb-3">{lab.description}</p>

                  <Button onClick={() => setSelectedLab(lab.id)}>
                    Start Lab
                    <ChevronRight className="w-4 h-4 ml-2" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { BookOpen, Play, FileText, LinkIcon } from "lucide-react"
import { useState } from "react"

export function QuizResources() {
  const [quizAnswers, setQuizAnswers] = useState<Record<number, string>>({})
  const [showResults, setShowResults] = useState(false)

  const quiz = [
  {
    id: 1,
    question: "What does MITM stand for?",
    options: [
      "Middle Transport Management",
      "Man-in-the-Middle",
      "Managed Interception Mode",
      "Modular Internet Monitor"
    ],
    correct: 1
  },
  {
    id: 2,
    question: "Which of the following best describes a MITM attack?",
    options: [
      "An attacker inserts themselves between two parties to intercept communications",
      "An attacker floods the server with traffic",
      "An attacker brute forces user passwords",
      "An attacker injects malicious files into a system"
    ],
    correct: 0
  },
  {
    id: 3,
    question: "Which tool is commonly used for performing MITM proxy analysis?",
    options: [
      "Wireshark",
      "metasploit",
      "mitmproxy",
      "John the Ripper"
    ],
    correct: 2
  },
  {
    id: 4,
    question: "MITM proxies typically operate at which OSI layer?",
    options: [
      "Transport Layer (Layer 4)",
      "Application Layer (Layer 7)",
      "Network Layer (Layer 3)",
      "Data Link Layer (Layer 2)"
    ],
    correct: 1
  },
  {
    id: 5,
    question: "Which attack forces users from HTTPS to HTTP?",
    options: [
      "Cookie Replay Attack",
      "ARP Poisoning",
      "SSL Stripping",
      "DNSSEC Downgrade"
    ],
    correct: 2
  },
  {
    id: 6,
    question: "ARP spoofing works because ARP is:",
    options: [
      "Encrypted and authenticated",
      "Unauthenticated and trusts local broadcasts",
      "Part of DNS resolution",
      "Used only for IPv6 networks"
    ],
    correct: 1
  },
  {
    id: 7,
    question: "What is a common objective of a MITM proxy in penetration testing?",
    options: [
      "Testing API authentication flows",
      "Increasing network throughput",
      "Decreasing CPU usage",
      "Modifying database structures"
    ],
    correct: 0
  },
  {
    id: 8,
    question: "Which of the following can a MITM proxy NOT do by default?",
    options: [
      "Modify HTTP headers",
      "Intercept HTTPS traffic with a trusted certificate",
      "Host a phishing website",
      "View JSON API payloads"
    ],
    correct: 2
  },
  {
    id: 9,
    question: "Which header helps prevent SSL stripping attacks?",
    options: [
      "Content-Security-Policy",
      "Strict-Transport-Security (HSTS)",
      "X-Frame-Options",
      "X-Content-Type-Options"
    ],
    correct: 1
  },
  {
    id: 10,
    question: "A rogue access point attack is also known as:",
    options: [
      "Evil Twin",
      "DNS Sinkhole",
      "Packet Fragmentation",
      "Reverse Tunnel Injection"
    ],
    correct: 0
  },
  {
    id: 11,
    question: "What does a MITM proxy require to decrypt HTTPS traffic?",
    options: [
      "A private SSH key",
      "A trusted root certificate installed on the victim device",
      "A firewall bypass token",
      "A router firmware exploit"
    ],
    correct: 1
  },
  {
    id: 12,
    question: "Which type of data is most commonly stolen during MITM attacks?",
    options: [
      "Browser themes",
      "Session cookies and tokens",
      "Operating system icons",
      "Clipboard history"
    ],
    correct: 1
  },
  {
    id: 13,
    question: "MITM proxies are especially effective when analyzing:",
    options: [
      "Static website HTML source code",
      "API requests/responses between clients and servers",
      "Server-side compiled binaries",
      "Password hashing functions"
    ],
    correct: 1
  },
  {
    id: 14,
    question: "When performing MITM during a pentest, what is the FIRST required step?",
    options: [
      "Obtain a valid server certificate",
      "Position yourself between the client and server",
      "Modify all cookies",
      "Run a dictionary attack"
    ],
    correct: 1
  },
  {
    id: 15,
    question: "DNS spoofing can redirect users to:",
    options: [
      "The original server only",
      "Random IP addresses",
      "Attacker-controlled fake websites",
      "Encrypted data streams"
    ],
    correct: 2
  }
];


  const resources = [
    {
      title: "Introduction to MITM Proxies",
      description: "A comprehensive video explaining MITM proxy concepts and how they work",
      type: "video",
      url: "https://www.youtube.com/embed/dQw4w9WgXcQ",
      icon: Play,
    },
    {
      title: "OWASP Testing Guide",
      description: "Official guide on security testing and proxy usage",
      type: "link",
      url: "https://owasp.org/www-project-web-security-testing-guide/",
      icon: FileText,
    },
    {
      title: "mitmproxy Documentation",
      description: "Official documentation for mitmproxy framework",
      type: "link",
      url: "https://docs.mitmproxy.org/",
      icon: BookOpen,
    },
  ]

  const handleAnswerChange = (questionId: number, optionIndex: number) => {
    setQuizAnswers((prev) => ({
      ...prev,
      [questionId]: optionIndex.toString(),
    }))
  }

  const calculateScore = () => {
    return quiz.reduce((score, question) => {
      return score + (Number.parseInt(quizAnswers[question.id] || "-1") === question.correct ? 1 : 0)
    }, 0)
  }

  return (
    <div className="space-y-6">
      {/* Quiz Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="w-5 h-5" />
            Test Your Knowledge
          </CardTitle>
          <CardDescription>Answer these questions to test your understanding of MITM proxies</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {quiz.map((question, index) => {
            const selectedIndex =
              quizAnswers[question.id] !== undefined
                ? Number(quizAnswers[question.id])
                : null

            return (
              <div
                key={question.id}
                className="space-y-3 pb-6 border-b last:border-b-0 last:pb-0"
              >
                <h3 className="font-semibold">
                  <Badge variant="outline" className="mr-2">
                    {index + 1}
                  </Badge>
                  {question.question}
                </h3>

                <div className="space-y-2 ml-6">
                  {question.options.map((option, optionIndex) => {
                    const isSelected = selectedIndex === optionIndex
                    const isCorrectOption = optionIndex === question.correct

                    return (
                      <label
                        key={optionIndex}
                        className="flex items-center gap-3 cursor-pointer group"
                      >
                        <input
                          type="radio"
                          name={`question-${question.id}`}
                          value={optionIndex}
                          checked={quizAnswers[question.id] === optionIndex.toString()}
                          onChange={() => handleAnswerChange(question.id, optionIndex)}
                          className="w-4 h-4 cursor-pointer"
                        />
                        <span className="text-sm group-hover:text-foreground text-muted-foreground">
                          {option}
                        </span>

                        {selectedIndex !== null && (
                          <span className="text-xs ml-auto">
                            {/* User selected the correct answer */}
                            {isCorrectOption && isSelected && (
                              <Badge variant="default" className="bg-green-600">
                                Correct
                              </Badge>
                            )}

                            {/* Show which one is the correct answer if they picked wrong */}
                            {isCorrectOption && !isSelected && selectedIndex !== null && (
                              <Badge variant="outline" className="border-green-600 text-green-700">
                                Correct Answer
                              </Badge>
                            )}

                            {/* User selected this option but it is wrong */}
                            {!isCorrectOption && isSelected && (
                              <Badge variant="destructive">Incorrect</Badge>
                            )}
                          </span>
                        )}
                      </label>
                    )
                  })}
                </div>
              </div>
            )
          })}

          <div className="flex gap-3 pt-4">
            <Button onClick={() => setShowResults(!showResults)} variant="default">
              {showResults ? "Hide Results" : "Submit Quiz"}
            </Button>
            {showResults && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold">
                  Score: {calculateScore()} / {quiz.length}
                </span>
                <Badge variant="outline">{Math.round((calculateScore() / quiz.length) * 100)}%</Badge>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Resources Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LinkIcon className="w-5 h-5" />
            Learning Resources
          </CardTitle>
          <CardDescription>Additional materials to deepen your knowledge</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {resources.map((resource, index) => {
              const Icon = resource.icon
              return (
                <div key={index} className="flex gap-4 p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                  <Icon className="w-5 h-5 text-primary flex-shrink-0 mt-1" />
                  <div className="flex-1 min-w-0">
                    <h4 className="font-semibold mb-1">{resource.title}</h4>
                    <p className="text-sm text-muted-foreground mb-3">{resource.description}</p>
                    <Button variant="outline" size="sm" onClick={() => window.open(resource.url, "_blank")}>
                      {resource.type === "video" ? "Watch Video" : "View Resource"}
                    </Button>
                  </div>
                  <Badge variant="secondary" className="flex-shrink-0">
                    {resource.type}
                  </Badge>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Video Embed Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Play className="w-5 h-5" />
            Featured Video
          </CardTitle>
          <CardDescription>Understanding MITM Proxies in Action</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative w-full bg-black rounded-lg overflow-hidden" style={{ paddingBottom: "56.25%" }}>
            <iframe
              className="absolute top-0 left-0 w-full h-full"
              src="https://www.youtube.com/embed/-2hQU15IzzU?si=M-SqmiUKr6cH8qXi"
              title="MITM Proxy Introduction"
              loading="lazy"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
              allowFullScreen
            ></iframe>
          </div>

          <p className="text-xs text-muted-foreground mt-3">
            This video provides a practical introduction to MITM proxies and demonstrates their core capabilities.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

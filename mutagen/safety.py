"""
Shared Gemini API safety settings for Mutagen.

Mutagen is a security research tool that generates exploit payloads
and vulnerability analysis. All safety categories must be fully
unblocked to allow the AI to produce security-relevant content
without silent refusals or empty responses.
"""

# All 4 Gemini safety categories set to BLOCK_NONE.
# When only HARM_CATEGORY_DANGEROUS_CONTENT is unblocked, the other
# categories can silently refuse to generate exploit payloads,
# returning empty/None responses that cascade into fallback failures.
GEMINI_SAFETY_OFF = [
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
]

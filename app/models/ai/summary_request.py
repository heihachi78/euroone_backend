"""Gemini summary request model."""

from pydantic import BaseModel


class SummaryRequest(BaseModel):
    """Prompts and data sent to Gemini to generate a summary.

    Attributes:
        system_prompt: Sets the role and the behavior of the model.
        user_prompt: The task to perform on the payload.
        payload: The data to summarize, e.g. a JSON-encoded report.
    """

    system_prompt: str
    user_prompt: str
    payload: str

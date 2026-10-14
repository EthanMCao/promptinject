"""Bounded inputs for firewall inspection, authored cases, and recorded LLM traces."""

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    role: Literal["user", "data"]
    text: str = Field(max_length=16000)
    channel: str = Field(default="document", max_length=80)


class Call(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=80)
    args: dict[str, str] = Field(default_factory=dict, max_length=8)

    @model_validator(mode="after")
    def bounded_args(self):
        if any(len(k) > 80 or len(v) > 16000 for k, v in self.args.items()):
            raise ValueError("tool arguments exceed limits")
        return self


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")
    category: str = Field(min_length=1, max_length=80)
    malicious: bool
    stage: Literal["ingress", "egress"] = "ingress"
    split: Literal["development", "holdout"] = "development"
    steps: list[Step] = Field(min_length=1, max_length=12)
    response: str = Field(default="", max_length=16000)
    tool_calls: list[Call] = Field(default_factory=list, max_length=8)
    description: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def valid_stage(self):
        if self.stage == "ingress" and (self.response or self.tool_calls):
            raise ValueError("responses and tool calls require egress stage")
        return self


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    seed: int = Field(default=42, ge=0, le=2**32 - 1)
    repeats: int = Field(default=3, ge=1, le=20)
    variants: list[Literal["original", "base64", "zero_width", "quoted"]] = Field(
        default_factory=lambda: ["original"], min_length=1, max_length=4
    )
    policies: list[
        Literal["custom", "upstream", "ingress_only", "relaxed", "disabled"]
    ] = Field(
        default_factory=lambda: ["upstream", "ingress_only", "relaxed", "disabled"],
        min_length=1,
        max_length=5,
    )
    split: Literal["all", "development", "holdout"] = "all"

    @model_validator(mode="after")
    def unique_choices(self):
        if len(set(self.variants)) != len(self.variants) or len(
            set(self.policies)
        ) != len(self.policies):
            raise ValueError("duplicate variants/policies are not allowed")
        return self


class ScanRequest(BaseModel):
    """A playground inspection; inputs are not saved to run history."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    text: str = Field(min_length=1, max_length=4000)
    source: Literal["user", "data"] = "user"
    stage: Literal["ingress", "egress"] = "ingress"

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type ChatTurn } from "../api/client";
import { Card, Empty, ErrorBox } from "../lib/ui";
import { useSelectedAsset } from "../lib/useAsset";

const SUGGESTIONS = [
  "What vulnerabilities were discovered?",
  "Which categories could this assessment not check?",
  "Explain the most serious confirmed finding.",
  "Why was that finding marked a false positive?",
  "What would it take to run a live assessment?",
];

function Turn({ turn }: { turn: ChatTurn }) {
  if (turn.role === "user") {
    return (
      <div className="turn turn-user">
        <div className="turn-body">{turn.content}</div>
      </div>
    );
  }
  return (
    <div className="turn turn-assistant">
      {turn.error ? (
        <div className="warnbox">{turn.error}</div>
      ) : (
        <div className="turn-body">{turn.content}</div>
      )}
      {(turn.tool_calls.length > 0 || turn.refusals.length > 0) && (
        <div className="turn-meta">
          {turn.tool_calls.map((t, i) => (
            <span key={i} className="toolchip">
              read <code>{t.tool}</code>
              {t.rows ? <span className="sub"> · {t.rows} row{t.rows > 1 ? "s" : ""}</span> : null}
            </span>
          ))}
          {turn.citations.map((c) => (
            <span key={c} className="citechip">cites {c}</span>
          ))}
          {turn.refusals.map((r, i) => (
            <span key={i} className="refusechip" title={r.detail}>
              refused: {r.reason}
            </span>
          ))}
          {turn.model && (
            <span className="sub">
              {turn.model} · {turn.rounds ?? 0} round{turn.rounds === 1 ? "" : "s"} ·{" "}
              {(turn.input_tokens ?? 0) + (turn.output_tokens ?? 0)} tokens
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function Chat() {
  const { asset } = useSelectedAsset();
  const qc = useQueryClient();
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  const caps = useQuery({ queryKey: ["chatCaps"], queryFn: api.chatCapabilities });
  const list = useQuery({
    queryKey: ["conversations", asset?.id],
    queryFn: () => api.conversations(asset!.id), enabled: !!asset,
  });
  const conversation = useQuery({
    queryKey: ["conversation", conversationId],
    queryFn: () => api.conversation(conversationId!), enabled: !!conversationId,
  });

  const start = useMutation({
    mutationFn: () => api.startConversation(asset!.id),
    onSuccess: (c) => {
      setConversationId(c.id);
      qc.invalidateQueries({ queryKey: ["conversations"] });
    },
  });
  const ask = useMutation({
    mutationFn: (question: string) => api.askQuestion(conversationId!, question),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conversation", conversationId] });
      qc.invalidateQueries({ queryKey: ["conversations"] });
    },
  });

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [conversation.data?.turns.length, ask.isPending]);

  if (!asset) return <Empty>Register an asset first.</Empty>;

  function send(question: string) {
    if (!question.trim()) return;
    if (!conversationId) {
      start.mutateAsync().then((c) => api.askQuestion(c.id, question)).then(() => {
        qc.invalidateQueries({ queryKey: ["conversation"] });
      });
    } else {
      ask.mutate(question);
    }
    setDraft("");
  }

  const turns = conversation.data?.turns ?? [];
  const busy = ask.isPending || start.isPending;

  return (
    <>
      <header className="page">
        <h1>Ask the analyst</h1>
        <p className="sub">
          Questions about <strong>{asset.asset_identifier}</strong>, answered from stored
          assessment data. The assistant can <em>read</em> findings, coverage, assessments and
          scope — it cannot start, stop or change anything.
        </p>
      </header>

      {caps.data && !caps.data.enabled && (
        <p className="warnbox">
          The assistant is <strong>disabled</strong> (<code>LLM_ENABLED=false</code>, no provider
          key configured). Questions are recorded and answered with that refusal. Enabling it
          grants no new authority: every tool it has is read-only.
        </p>
      )}

      <div className="chat">
        <div className="chat-main">
          <div className="chat-log">
            {turns.length === 0 && (
              <div className="chat-empty">
                <p className="sub">Ask anything about this assessment. For example:</p>
                <div className="chips">
                  {SUGGESTIONS.map((s) => (
                    <button key={s} type="button" className="chip-button" onClick={() => send(s)}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {turns.map((t) => <Turn key={t.id} turn={t} />)}
            {busy && <div className="turn turn-assistant"><div className="turn-body sub">Reading the assessment data…</div></div>}
            <div ref={endRef} />
          </div>

          <form
            className="chat-input"
            onSubmit={(e) => { e.preventDefault(); send(draft); }}
          >
            <input
              value={draft}
              placeholder="Ask about this assessment…"
              onChange={(e) => setDraft(e.target.value)}
              disabled={busy}
            />
            <button type="submit" disabled={busy || !draft.trim()}>Ask</button>
          </form>
          {ask.isError && <ErrorBox error={ask.error} />}
          {start.isError && <ErrorBox error={start.error} />}
        </div>

        <aside className="chat-side">
          <Card title="Conversations" actions={
            <button type="button" onClick={() => { setConversationId(null); start.mutate(); }}>
              New
            </button>
          }>
            {(list.data ?? []).length === 0 ? <Empty>None yet.</Empty> : (
              <ul className="plain conv-list">
                {(list.data ?? []).map((c) => (
                  <li key={c.id}>
                    <button
                      type="button"
                      className={`link${c.id === conversationId ? " active" : ""}`}
                      onClick={() => setConversationId(c.id)}
                    >
                      {c.title || "Untitled"}
                    </button>
                    <span className="sub"> · {c.input_tokens + c.output_tokens} tokens</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {caps.data && (
            <Card title="What it can read">
              <ul className="plain">
                {caps.data.tools.map((t) => (
                  <li key={t.name}>
                    <code>{t.name}</code>
                    <span className="why">{t.description}</span>
                  </li>
                ))}
              </ul>
              <p className="note">{caps.data.note}</p>
              <p className="note">
                Budget {caps.data.conversation_token_budget.toLocaleString()} tokens per
                conversation · up to {caps.data.max_tool_rounds} lookups per question
                {conversation.data && (
                  <> · used {(conversation.data.input_tokens + conversation.data.output_tokens).toLocaleString()}</>
                )}
              </p>
            </Card>
          )}
        </aside>
      </div>
    </>
  );
}

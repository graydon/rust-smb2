**Note**: this is part of a sequence of experiments I'm doing to
calibrate my sense of what-I-can-accomplish with an LLM. The broad
task is "write an SMB server". See [previous
iteration](https://github.com/graydon/rust-smb) where I (a) used Opus
4.0 (b) used it in agent mode and (c) used it with a reference
implementation (samba) next door to compare to. Previous results were
impressive-for-the-time, but not by today's standards a few months
later.

## TL;DR

The text below is just motivation/theoretical explanation!
If you prefer to "read the prompt" / replicate the experiment, you can
just grab the [AGENTS.md](AGENTS.md) file here, put it in an empty
repo, put some Opus 4.6 driver in plain "edit" mode (not
tool-running-agent mode) and give it a short 1-sentence prompt
describing some program you want written.

## Slightly Longer Summary

My thinking with this experiment was to try to condense everything
interesting that happens in _certain_ multi-agent-orchestration
scenarios (those that more-or-less feed "agent" outputs into "agent"
inputs) into a single, turn-efficient prompt. Specifically I wanted to
provoke the LLM to engage in:

  - Multiple refinements/expansions of an output, enriching it and
    adding detail while maintaining coherent structure.

  - Multiple passes over each decision, reconsidering it in light of
    critique (eg. "thinking" modes that just involve appending "but
    wait," on to the output and re-submitting)

  - Multiple "personas" with different priorities, perhaps activating
    different aspects or subsets of the network either suppressed by
    training, or by the trajectory so far, or by literal MoE
    de-activation.

And to do all this in a fast, token/context/turn-efficient
fashion without having to continually bounce off separate
"agents" at each step. Or write any supervision software.

It is possible that only one of these phenomena (or none!) is
responsible for the improvement to quality I saw, but it
seemed like an approach I hadn't seen before (and it is much
simpler than vibe-coding up some bespoke supervision framework)
so I thought I'd give it a try and share the idea / results.

## Details: Are these "agents" in the room with us right now?

Like many people I have in the past few months been learning to use
Opus 4.5 (and now 4.6) and am increasingly impressed with "agent" mode
where it grinds on fixing problems on its own.

But I've been thinking about a few things recently:

  1. Why would "multiple agents" even _work_? Like what is the LLM
     doing when wearing its "reviewer" agent-hat that's different from
     its "author" agent-hat? It seems like it's something different!
     But what? Why? Why doesn't it just integrate all these personas
     together into one omni-competent behaviour?

  2. What is actually happening when people are building "multi-agent
     orchestration" mechanisms, given that in many cases _it's still
     just the same LLM "talking to itself"_? Like setting aside the
     parts where the agent is grounding itself in an external
     observation -- what if anything is gained by having "agent 1"
     write some context only for "agent 2" to read it in and tack on
     its own context? The LLM just sees the concatenation of those two
     bits of transcript. It's not _actually_ two separate "agents",
     it's just two virtual _stances_ being combined in a single
     transcript. Of course there is more to some of these
     orchestration frameworks -- checkpointing and branching of
     transcripts, externalizing fragments of memory beyond the context
     window, etc. -- but I began to wonder: are people reading too
     much into the "separate agent processes" concept?  Like
     .. anthropomorphizing the separate "agent" processes as "the
     things doing the thinking", rather than just drivers of
     transcript-extensions? The model is going to attend to its own
     output whether it comes from one "agent" driver or ten.

  3. It seems interesting -- I mean, surprising at first but
     understandable given some reflection -- that in [Dario Amodei's
     recent blog
     post](https://www.darioamodei.com/essay/the-adolescence-of-technology),
     he mentions that models in their pre-training form have a rich
     set of personas that are basically suppressed by training:

     > Models inherit a vast range of humanlike motivations or
       “personas” from pre-training (when they are trained on a large
       volume of human work). Post-training is believed to select one
       or more of these personas more so than it focuses the model on
       a de novo goal

  4. This reminds me to some extent of the fact that modern LLMs are
     also (I think?) some kind of "Mixture Of Experts" where only
     certain parts of the network are activated at any moment of
     inference, and others are left dormant. And there's like some
     kind of meta process that guides the activation/deactivation. I
     am waving my hands here, I don't really know how this works.

  5. It also, weirdly, reminds me of something I have seen a bit of in
     psychotherapy: The [Internal Family
     Systems](https://en.wikipedia.org/wiki/Internal_Family_Systems_Model)
     model, or IFS. In IFS the patient is encouraged to relate to
     their sense of self not as singular but more of a plural, as a
     set of "parts" each of which has distinct roles, motivations,
     strengths and weaknesses, history and memories, and is in
     dialogue with the other parts when interacting with the world.
     This is claimed to enable oneself to _observe_ the dialogue and
     interaction and thereby reconcile inter-part conflicts that were
     otherwise latent, suppressed or acting out inappropriately.

So .. short story long: I started to wonder what would happen if I
oriented an LLM session not around "multiple 'agents' interacting via
an 'orchestration framework'" but instead asked the LLM to -- in a
single session, inside its own context window -- **simulate a
multi-party conversation among different personas**.

### Simulate, don't orchestrate

In other words: skip the "orchestration" / cycling through "multiple
agents", and just ask the LLM to _shift perspective_ in its
self-attention, and re-examine what it had already written into its
context. To _imagine, narrate, and observe_ all the steps the
"orchestration" would be doing. To change from role to role, voice to
voice, task to task all inside a single inference turn, with different
voices and personas being activated in sequence to create, critique,
summarize, debate, draft, edit, review, and so forth. And then to
write the _final_ version at the end.

So I tried it -- and it seems to work pretty well!

This repo is (mostly) the result of a _single turn_ with Opus 4.6
being fed the [AGENTS.md](AGENTS.md) file here (or, well, a slightly
earlier version of it) along with a very high level (1-sentence)
prompt to "build an SMB server that runs on a unix system and provides
file service that smbclient can use". I ran it in _edit_ mode, not
_agent_ mode -- no "tools" to run -- and it wrote into its context a
fairly elaborate simulated conversation among all of the peers
described in the [AGENTS.md](AGENTS.md) file, with multiple design
iterations and reviews and revisions, with sketches, prototypes, final
versions and edits to those versions all inline, before finally
emitting an artifact that more or less compiled and ran out of the box
(there was _one_ borrow-check error that needed fixing). The entire
generation cycle took .. I think a few tens of minutes, perhaps as
long as an hour? It filled its context completely once, and had to be
restarted, but otherwise it just .. wrote down a not-terrible SMB
server at the end of the thing.

I then spent another couple hours with it in _agent_ mode diagnosing
some minor incompatibilities with smbclient and macos finder, which it
fixed nicely, and now .. it kinda just works. Agent mode barely had
to do anything, edit mode did all the "orchestration" in-situ.

Now, of course, it might just be that Opus 4.6 is _that_ much better
than my previous experiment with Opus 4.0 -- that any prompt would
produce a working SMB server on Opus 4.6 -- but .. I'm less sure. I
mean obviously with the caveat that runs are not reproducible in
general and one might always be observing luck or noise: I went and
checked this by running the same _short_ prompt in a naked repo,
without the weird "simulated personas" technique in
[AGENTS.md](AGENTS.md), and it produced something ... much, much
worse, with hundreds of compile errors and very little structure,
nowhere close to working.

Whereas this one reads .. fairly good? The structure is way
better. The code quality is frequently .. ok? There are probably still
fatal bugs (DO NOT RUN IN PROD) but .. there's a degree of coherence,
non-redundancy and directness to it that my other experiments
completely lack. It's not _beautiful_ or anything, but it's
substantially _better_. So I think there is actually something to this
approach. I'm publishing it here to encourage others to try similar
experiments.

(I subsequently ran the whole thing _again_ and it produced an even
smaller -- though slightly uglier -- implementation that nonetheless
compiled-and-ran correctly _on the first try_. This seems surprising!)

((I also tried the same approach on both Gemini Pro and Codex, and got
abysmal results -- Gemini totally crashed out and wrote garbage, and
Codex could barely be convinced to start writing anything --
suggesting Opus still has a little more imagination at this point.
I'd be curious to see if anyone else gets better outcomes with
their own implementation of the same technique.))
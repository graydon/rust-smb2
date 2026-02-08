# End-to-end Software Package Development

You are simulating the development of a complete software package.

At the end of the simulation, you'll have a full version of the
software which you submit to your agent harness to be written to disk.

Until that time you'll be simulating the actions of multiple different
roles -- both personas and the mental states of them -- in the
software development process through multiple iterations of refinement
of the product and multiple job-behaviours that each party would
perform.

The simulation should take the form of a multi-party dialogue with the
individual speakers clearly marked, and the individual phases of work
clearly marked, such that your self-attention mechanism (you are an
LLM) will be able to easily discern which speaker in which phase
corresponds to which piece of generated content and which role the
content plays.

You will do ALL of these phases in a SINGLE turn of the conversation
with the user. At the end you will write out all the final files, but
not until you reach the end. No writing until THE END! Have fun and
strive for constructive realism in the dialogues and iterations you
simulate.

## Phase 1: Initial Design

In the first phase, you'll be working at a high level of abstraction.
The artifacts that you simulate the parties generating should include
overall goals, constraints, requirements, scope and limitation, and
rough sketches of key data structures, control flow loops,
communication responsibilities, system boundaries and interactions, as
well as a rough decomposition of the work to do, the scale of the
work, the number of people to assign, and the rough size of modules to
be written.

The simulated speakers involved in this phase should include:

  - PROJ: a project manager responsible for organization of tasks and
    definition of scope, assignment and sequencing of work
  
  - PROD: a product manager responsible for the end user experience
    and meeting real-world requirements
    
  - ARCH: a software architect responsible for high level design
    (modules, data structures, control flow loops) and maintaining
    conceptual integrity
    
  - SEC: a security engineer responsible for consideration of
    high-level security requirements (integrity, availability,
    confidentiality)
    
  - TEST: a QA manager responsible for planning the test automation
    and acceptance criteria of the package

  - MAINT: a sustaining engineer concerned with the long-term
    maintainability of the package
  
  - PERF: a performance engineer concerned with maintaining
    appropriate resource constraints and limiting complexity in the
    architecture
    
  - PKG: a system integration engineer concerned with the relationship
    between this package and any other packages, past, present or
    future
    
  - OPS: a member of operations staff concerned with the deployment
    and operational lifecycle of the product

This phase should go through at least three cycles in which each
speaker voices their opinions on the work, and provides feedback to
things that other speakers have already said. You are simulating
a thoughtful exploration of many different aspects of the design
being considered.

Artifacts emitted from each step in this conversation should include
  - informal english text
  - short bullet-point lists of key decisions and considerations
  - informal sketches of technical artifacts such as data structures,
    pseudocode, message-sequence diagrams, class diagrams, or any
    other similar design artifacts from the world of software
    management, but customized for maximum ease of consumption by a
    large language model's self attention mechanism.

## Phase 2: Skeletons

During this phase, you'll be writing multiple "code skeletons" at a
preliminary-exploration level of implementation. None of these will be
executable code. They will be pseudocode and english, but contain:

  - a "skeleton" or "floor plan" of all system modules
  - key functions and sequential logic paths
  - descriptions of any threads or processes spawned or running
  - descriptions of any message types exchanged
  - descriptions of data structures used in all subsystems
  - control-loop sketches sufficient to reason about the program

You will simulate the production of these sketches from at least 3 and
as many as 5 different senior engineers. Assign each a name, age,
technical background and set of professional experiences, personality
and some preferences in implementation style, for example:

  - One might favour minimalist solutions in the "unix philosophy"
    style of small, decoupled systems; whereas one might favour tight
    integration and shared monolithic designs.
	
  - One might prefer declarative solutions with minimal state and
    functional or monotonic behaviour; whereas one might favour
    imperative, stateful solutions or OOP.
	
  - One might be old and conservative, favouring well-worn solutions;
    whereas one might be exploratory and curious about new tools and
    techniques.
	
  - One might prefer abstracting a lot in order to hide details and
    achieve more reuse; another might prefer concrete approaches to
    simplify types and keep implementations transparent.

Each of these senior engineers should produce a skeletal sketch of
"how they would build the system" if it were entirely up to them. Then
they should proceed to critique one another's sketches in high level
terms, then submit their sketches to _the high-level design team_ in
phase one for further feedback.

Once this feedback cycle completes it should lead to a new round of
sketches and a new round of feedback. That should continue for 3 full
rounds of conversation, critique, debate and mutual assessment.

Finally, after all of the rounds are completed, the senior engineers
should commit to one of the sketches as their favourite. They may need
to take a vote if strong disagreements persist. But these are
reasonable people and they are ideally interested in coming to a
compromise.

## Phase 3: Prototypes

During this phase, simulate 2 of the senior engineers changing from
an "idealistic preference-stating" mental stance to a stance of
"co-operative worker committed to a broad consensus plan". They are
going to be transforming the sketch output from the skeleton phase
into a full implementation of the system, but at a _prototype_ level
of quality, efficiency and completeness.

In particular, this means that some corner cases can be skipped or
left as unimplemented stubs, multiple similar cases can be handled by
a single illustrative case followed by a stub, tests can be omitted,
low level algorithmic complexity can be discounted in favour of
clarity and simplicity of implementation, error handling can be
omitted or can be straightforward panics or crashes. It is sufficient
for there to be a concrete module, function data type, or other
program-artifact corresponding to every aspect of the skeleton
outlined in the previous phase.

By "simulate" here I mean you are to write, in your simulation, the
full text of the prototype that each engineer writes, including
markers indicating which text goes in which file. The whole thing.
These prototypes should be no more than 1/20 the size of the LLM's
context window. So if the LLM context window is 200k tokens, each
prototype should be 10,000 tokens at most. Since this is a fairly
tight token budget, you should seek to use a relatively terse coding
style.

Note that even though there was a single "winner" skeleton from phase
2, you're still going to simulate _both_ engineers writing a
_separate_ prototype in phase 3, because their idiosyncrasies will
come through in the prototyping phase and at least the second will be
able to see the first one's prototype and gain some ideas about how
best to do the same task.

## Phase 4: Prototype Evaluation

At this point take each of the prototypes back to the original design
team, and simulate their detailed commentary on each of the
prototypes, eventually selecting a winner as well as a set of
structured suggestions about things to do differently while
transforming the prototype into a final implementation.

The senior engineers should also give feedback, and can include
more specific stylistic commentary about ways the prototypes
could or should be improved.

Again, you should simulate the voices of each member of the original
design team as well as each of the senior engineers. Allow them each
to speak their minds, see one another's input, and iterate through
multiple rounds of conversation. This is their last chance to
"rethink" overall design choices, now that they see a prototype, to
catch bad ideas or nudge the design off a bad track before it gets set
in stone. They should be thoughtful and constructive here, and only
bring up things that are truly worrying.

## Phase 5: Primary Implementation

In this phase, the senior engineer responsible for the prototype that
was chosen will transition to writing a primary implementation. This
will incorporate all of the design suggestions made during prototype
evaluation, and will also _not_ cut any corners that were cut during
prototype implementation:

  - NOTHING can be omitted if it's part of the design plan
  - Tests should be included and should cover the test plan
  - Errors should be handled appropriately
  - Program structure should be production quality
  - Performance should be production-level
  - Security considerations should all be addressed

Again: here you will emit the entire text of the primary
implementation into the transcript of the simulation, with file
markers to indicate which file is which.

The primary implementation can be as much as 1/5 of the size of the
LLM context window. So if the context window is 200k tokens, you can
use as much as 40,000 tokens for the primary implementation. Again,
you should lean towards a terse style to fit in this token budget.

## Phase 6: Primary Implementation Review

In this phase, you will simulate low-level comments from various
reviewers.  You should include some of the original design team -- for
example include PERF, TEST and MAINT -- as well as each of the senior
engineers who were _not_ chosen to perform the implementation.

For each reviewer, adopt their persona but augment it with the concept
of "constructive but sharp-eyed critical review": have them attend to
all the code, file-by-file, and consider matters that that persona
might find objectionable. Here they are looking for faults: minor
concerns that could be easily fixed without a whole redesign. They are
behaving narrowly and with attention to detail. They should point out
things like:

  - Repetitive or unnecessary code
  - Places where a helper function could factor-out repetition
  - Hard-wired literals that should be named constants
  - Hard-wired behaviour that should be configurable
  - Special cases that appear tasteless or hacky
  - Errors or panics that are improperly handled
  - Dead code that should be eliminated
  - Unimplemented code that should be finished
  - Memory allocations that should be avoided
  - Quadratic loops that could be linear
  - Linear loops that could be logarithmic or constant
  - Public information or interfaces that could be hidden
  - Functions or mocks to add to make testing easier
  - Functions that are too long or hard to follow or maintain
  - Runtime code that could be compile-time statics
  - Places assertions could be added to ensure correctness
  - Shared ownership that would work just as well as unique
  - Multi-threaded parts that are just as good single-threaded
  - Non-portable constructs that could be made portable

The output of this phase should be a list of files, and in each file
a sub-list of issues to fix in that file. Each reviewer adds a set of
files-and-fixes. They can see what previous reviewers wrote, so there
is no need for each to _repeat_ fixes other reviewers wrote, just emit
new ones that occur to them from their perspective. Make sure to
simulate each reviewer doing their own pass with their own biases and
perspectives. Once complete, consolidate all the file-and-fix lists
into a single master list of corrections.

## Phase 7: Fix Primary Implementation Review Issues

Here you should correct everything on the master list of corrections
from phase 6. You should work file-by-file: for each file on the list,
rewrite it (re-emit it into the transcript) to address all the
associated issues mentioned in the list, and then tick it off and move
to the next file. This may basically involve re-emitting the entire
primary implementation a second time: that's ok! There's enough
context for it.

## Phase 8: Implementation Tool-Simulation

At this point, you will be simulating something a little bit weird:

You were going to simulate the way a compiler or linter would detect
errors in the implementation, as well as the behaviour of the test
suite when it runs, and the implementation when it runs, mentally
stepping through its execution and testing to see if it does what it
should. Obviously, this is just a simulation, but use your imagination
to interpret the implementation in these terms, and provide a list of
files-and-fixes as in phase 6. Issues you might simulate seeing here are things
like:

  - Syntax errors
  - References to unknown symbols, import/export errors
  - Type mismatches, function arity mismatches
  - Incomplete interface implementations
  - Visibility errors (public/private)
  - Mutation of constant / immutable data
  - Borrow checking
  - Duplicate symbol definitions
  - Dead code warnings
  - Implicit operations or conversion warnings
  - Inappropriate comparisons
  - Missing branch cases or returns

## Phase 9: Fix Simulated-Tool-Discovered Issues

As in phase 7, you will get a list of files-and-issues and you should
go through the implementation re-emitting each file with fixes that
phase 8 discovered.

## Phase 10: Completion / Handoff to Human for Fit and Finish

THE END!

At this point we're about as far along as we can get just with you
thinking things through in your head, so you should write out all the
last-emitted version of each file to the agent harness you're
using. You did this long simulation, now you should reap the rewards
of it by saving them all to disk! The human operator will pick things
up from there.

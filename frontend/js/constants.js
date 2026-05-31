/**
 * constants.js — shared UI constants.
 *
 * The register and flag lists are ordered the way we want them to appear
 * in the UI — grouped by purpose rather than by encoding order.
 * This matches how a debugger like gdb would display them.
 */

const REGISTERS = [
  'RAX', 'RBX', 'RCX', 'RDX',   // general purpose (return/arg/counter/data)
  'RSI', 'RDI',                   // source / destination index
  'RBP', 'RSP',                   // frame pointer / stack pointer
  'R8',  'R9',  'R10', 'R11',    // extended registers
  'R12', 'R13', 'R14', 'R15',
  'RIP',                          // instruction pointer — last, most prominent
];

const FLAGS = ['CF', 'PF', 'AF', 'ZF', 'SF', 'OF'];

// Human-readable tooltips for each flag
const FLAG_DESCRIPTIONS = {
  CF: 'Carry Flag',
  PF: 'Parity Flag',
  AF: 'Auxiliary Carry',
  ZF: 'Zero Flag',
  SF: 'Sign Flag',
  OF: 'Overflow Flag',
};

// How long the green flash on changed registers / flags lasts (ms).
// Should match CSS --highlight-duration.
const HIGHLIGHT_MS = 800;

// How many milliseconds between instructions when running continuously
const RUN_INTERVAL_MS = 80;

const API_BASE = '/api';

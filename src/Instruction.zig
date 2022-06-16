tag: Tag,

const Tag = enum {
    // Branches, Exception generating, and System instructions
    // zig fmt: off
    B,         // Branch
    BRK,       // Breakpoint Instruction
    CBZ,       // Compare and branch
    MRS,       // Move System register to general-purpose register
    MSR,       // Move general-purpose register to System register, Move immediate to PE state field
    NOP,       // No operation
    // zig fmt: on

    // Loads and stores
    LDR, // Load
    STR, // Store
    LDP, // Load pair
    STP, // Store pair
    LDN, // Load N-element structure
    STN, // Store N-element structure
    PRFM, // Prefetch memory
    LDADD,
    LDCLR,
    LDEOR,
    LDSET,
    LDMAX,
    LDMIN,
    STADD,
    STCLR,
    STEOR,
    STSET,
    STMAX,
    STMIN,
    SWP,
    CAS,
    ADDG,
    GMI,
    IRG,
    SUBG,
    SUBP,
    STG,
    LDG,
    CPY,
    SET,

    // Data processing
    ADD,
    SUB,
    CMP,
    AND,
    EOR,
    ORR,
    TST,
    MOV,
    ADR,
    BFM,
    BFC,
    BFI,
    BFX,
    EXTR,
    ASR,
    LSL,
    LSR,
    ROR,
    SXT,
    CMP,
    NEG,
    ADC,
    SBC,
    NGC,
    AND,
    BIC,
    EON,
};

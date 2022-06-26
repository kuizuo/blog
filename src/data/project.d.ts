export declare type Tag = {
    label: string;
    description: string;
    color: string;
};
export declare type TagType = 'favorite' | 'opensource' | 'product' | 'design' | 'javascript';
export declare type Project = {
    title: string;
    description: string;
    preview?: any;
    website: string;
    source?: string | null;
    tags: TagType[];
};
export declare const Tags: Record<TagType, Tag>;
export declare const TagList: TagType[];
export declare const sortedProjects: Project[];

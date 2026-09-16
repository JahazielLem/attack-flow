export type ObjectRecommendation = {
    id: string;
    color: string;
    name: string;
    subtitle: string;
    parentId?: string;
    isTieRecommendation?: boolean;
    defensiveObjectType?: "mitigation" | "detection";
};
